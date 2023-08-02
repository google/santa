/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include <functional>
#include <limits>
#include <string>

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool_platform_specific.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "absl/time/time.h"

namespace fsspool {

// Returns whether the given path exists and is a directory.
bool IsDirectory(const std::string& d) {
  struct stat stats;
  if (stat(d.c_str(), &stats) < 0) {
    return false;
  }
  return StatIsDir(stats.st_mode);
}

namespace {

constexpr absl::string_view kSpoolDirName = "new";
constexpr absl::string_view kTmpDirName = "tmp";

// Estimates the disk occupation of a file of the given size,
// with the following heuristic: A typical disk cluster is 4KiB; files
// usually get written to disk in multiples of this unit.
size_t EstimateDiskOccupation(size_t fileSize) {
  // kDiskClusterSize defines the typical size of a disk cluster (4KiB).
  static constexpr size_t kDiskClusterSize = 4096;
  size_t n_clusters = (fileSize + kDiskClusterSize - 1) / kDiskClusterSize;
  // Empty files still occupy some space.
  if (n_clusters == 0) {
    n_clusters = 1;
  }
  return n_clusters * kDiskClusterSize;
}

// Creates a directory if it doesn't exist.
// It only accepts absolute paths.
absl::Status MkDir(const std::string& path) {
  if (!IsAbsolutePath(path)) {
    return absl::InvalidArgumentError(
        absl::StrCat(path, " is not an absolute path."));
  }
  if (fsspool::MkDir(path.c_str(), 0700) < 0) {
    if (errno == EEXIST && IsDirectory(path)) {
      return absl::OkStatus();
    }
    return absl::ErrnoToStatus(errno, absl::StrCat("failed to create ", path));
  }
  return absl::OkStatus();
}

// Writes a buffer to the given file descriptor.
// Calls to write can result in a partially written file. Very rare cases in
// which this could happen (since we're writing to a regular file) include
// if we receive a signal during write or if the disk is full.
// Retry writing until we've flushed everything, return an error if any write
// fails.
absl::Status WriteBuffer(int fd, absl::string_view msg) {
  while (!msg.empty()) {
    const int n_written = Write(fd, msg);
    if (n_written < 0) {
      return absl::ErrnoToStatus(errno, "write() failed");
    }
    msg.remove_prefix(n_written);
  }
  return absl::OkStatus();
}

// Writes the given data to the given file, with permissions set to 0400.
// Roughly equivalent to file::SetContents.
absl::Status WriteTmpFile(const std::string& path, absl::string_view msg) {
  const int fd = Open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0400);
  if (fd < 0) {
    return absl::ErrnoToStatus(errno, "open() failed");
  }
  absl::Status write_status = WriteBuffer(fd, msg);
  Close(fd);
  if (!write_status.ok()) {
    // Delete the file so we don't leave garbage behind us.
    if (Unlink(path.c_str()) < 0) {
      // This is very unlikely (e.g. somehow permissions for the file changed
      // since creation?), still worth logging the error.
      return absl::ErrnoToStatus(
          errno, absl::StrCat("Writing to ", path,
                              " failed (and deleting failed too)"));
    }
    return write_status;
  }
  return absl::OkStatus();
}

// Renames src to dest. Equivalent to file::Rename.
absl::Status RenameFile(const std::string& src, const std::string& dst) {
  if (rename(src.c_str(), dst.c_str()) < 0) {
    return absl::ErrnoToStatus(
        errno, absl::StrCat("failed to rename ", src, " to ", dst));
  }
  return absl::OkStatus();
}

absl::StatusOr<size_t> EstimateDirSize(const std::string& dir) {
  size_t estimate = 0;
  absl::Status status =
      IterateDirectory(dir, [&dir, &estimate](const std::string& file_name) {
        /// NOMUTANTS--We could skip this condition altogether, as S_ISREG on
        /// the directory would be false anyway.
        if (file_name == std::string(".") || file_name == std::string("..")) {
          return;
        }
        std::string file_path = absl::StrCat(dir, PathSeparator(), file_name);
        struct stat stats;
        if (stat(file_path.c_str(), &stats) < 0) {
          return;
        }
        if (!StatIsReg(stats.st_mode)) {
          return;
        }
        // Use st_size, as st_blocks is not available on Windows.
        estimate += EstimateDiskOccupation(stats.st_size);
      });
  if (status.ok()) {
    return estimate;
  }
  return status;
}

std::string SpoolDirectory(absl::string_view base_dir) {
  return absl::StrCat(base_dir, PathSeparator(), kSpoolDirName);
}

bool operator==(struct timespec a, struct timespec b) {
  return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}

bool operator!=(struct timespec a, struct timespec b) { return !(a == b); }

}  // namespace

FsSpoolWriter::FsSpoolWriter(absl::string_view base_dir, size_t max_spool_size)
    : base_dir_(base_dir),
      spool_dir_(SpoolDirectory(base_dir)),
      tmp_dir_(absl::StrCat(base_dir, PathSeparator(), kTmpDirName)),
      max_spool_size_(max_spool_size),
      id_(absl::StrFormat("%016x", absl::Uniform<uint64_t>(
                                       absl::BitGen(), 0,
                                       std::numeric_limits<uint64_t>::max()))),
      // Guess that the spool is full during construction, so we will recompute
      // the actual spool size on the first write.
      spool_size_estimate_(max_spool_size + 1) {}

absl::Status FsSpoolWriter::BuildDirectoryStructureIfNeeded() {
  if (!IsDirectory(spool_dir_)) {
    if (!IsDirectory(base_dir_)) {
      if (absl::Status status = MkDir(base_dir_); !status.ok()) {
        return status;  // failed to create base directory
      }
    }

    if (absl::Status status = MkDir(spool_dir_); !status.ok()) {
      return status;  // failed to create spool directory;
    }
  }
  if (!IsDirectory(tmp_dir_)) {
    // No need to check the base directory too, since spool_dir_ exists.
    if (absl::Status status = MkDir(tmp_dir_); !status.ok()) {
      return status;  // failed to create tmp directory
    }
  }
  return absl::OkStatus();
}

std::string FsSpoolWriter::UniqueFilename() {
  std::string result = absl::StrFormat("%s_%020d", id_, sequence_number_);
  sequence_number_++;
  return result;
}

absl::StatusOr<size_t> FsSpoolWriter::EstimateSpoolDirSize() {
  struct stat stats;
  if (stat(spool_dir_.c_str(), &stats) < 0) {
    return absl::ErrnoToStatus(errno, "failed to stat spool directory");
  }

  if (stats.st_mtimespec != spool_dir_last_mtime_) {
    // Store the updated mtime
    spool_dir_last_mtime_ = stats.st_mtimespec;

    // Recompute the current estimated size
    return EstimateDirSize(spool_dir_);
  } else {
    // If the spool's last modification time hasn't changed then
    // re-use the current estimate.
    return spool_size_estimate_;
  }
}

absl::Status FsSpoolWriter::WriteMessage(absl::string_view msg) {
  if (absl::Status status = BuildDirectoryStructureIfNeeded(); !status.ok()) {
    return status;  // << "can't create directory structure for writer";
  }
  // Flush messages to a file in the temporary directory.
  const std::string fname = UniqueFilename();
  const std::string tmp_file = absl::StrCat(tmp_dir_, PathSeparator(), fname);
  const std::string spool_file =
      absl::StrCat(spool_dir_, PathSeparator(), fname);
  // Recompute the spool size if we think we are
  // over the limit.
  if (spool_size_estimate_ > max_spool_size_) {
    absl::StatusOr<size_t> estimate = EstimateSpoolDirSize();
    if (!estimate.ok()) {
      return estimate.status();  // failed to recompute spool size
    }
    spool_size_estimate_ = *estimate;
    if (spool_size_estimate_ > max_spool_size_) {
      // Still over the limit: avoid writing.
      return absl::UnavailableError(
          "Spool size estimate greater than max allowed");
    }
  }
  spool_size_estimate_ += EstimateDiskOccupation(msg.size());

  if (absl::Status status = WriteTmpFile(tmp_file, msg); !status.ok()) {
    return status;  // writing to temporary file
  }

  if (absl::Status status = RenameFile(tmp_file, spool_file); !status.ok()) {
    return status;  // "moving tmp_file to the spooling area
  }

  return absl::OkStatus();
}

FsSpoolReader::FsSpoolReader(absl::string_view base_directory)
    : base_dir_(base_directory), spool_dir_(SpoolDirectory(base_directory)) {}

int FsSpoolReader::NumberOfUnackedMessages() const {
  return unacked_messages_.size();
}

absl::Status FsSpoolReader::AckMessage(const std::string& message_path) {
  int remove_status = remove(message_path.c_str());
  if ((remove_status != 0) && (errno != ENOENT)) {
    return absl::ErrnoToStatus(
        errno,
        absl::Substitute("Failed to remove $0: $1", message_path, errno));
  }
  unacked_messages_.erase(message_path);
  return absl::OkStatus();
}

absl::StatusOr<std::string> FsSpoolReader::NextMessagePath() {
  absl::StatusOr<std::string> file_path = OldestSpooledFile();
  if (!file_path.ok()) {
    return file_path;
  }
  unacked_messages_.insert(*file_path);
  return file_path;
}

absl::StatusOr<std::string> FsSpoolReader::OldestSpooledFile() {
  if (!IsDirectory(spool_dir_)) {
    return absl::NotFoundError(
        "Spool directory is not a directory or it doesn't exist.");
  }
  absl::Time oldest_file_mtime;
  std::string oldest_file_path;
  absl::Status status = IterateDirectory(
      spool_dir_, [this, &oldest_file_path,
                   &oldest_file_mtime](const std::string& file_name) {
        std::string file_path =
            absl::StrCat(spool_dir_, PathSeparator(), file_name);
        struct stat stats;
        if (stat(file_path.c_str(), &stats) < 0) {
          return;
        }
        if (!StatIsReg(stats.st_mode)) {
          return;
        }
        if (unacked_messages_.contains(file_path)) {
          return;
        }
        absl::Time file_mtime = absl::FromTimeT(stats.st_mtime);
        if (!oldest_file_path.empty() && oldest_file_mtime < file_mtime) {
          return;
        }
        oldest_file_path = file_path;
        oldest_file_mtime = file_mtime;
      });
  if (!status.ok()) {
    return status;
  }

  if (oldest_file_path.empty()) {
    return absl::NotFoundError("Empty FsSpool directory.");
  }
  return oldest_file_path;
}

}  // namespace fsspool

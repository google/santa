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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H_
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H_

// Namespace ::fsspool::fsspool implements a filesystem-backed message spool, to
// use as a lock-free IPC mechanism.

#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

// Forward declarations
namespace fsspool {
class FsSpoolWriterPeer;
}

namespace fsspool {

// Enqueues messages into the spool. Multiple concurrent writers can
// write to the same directory. (Note that this class is only thread-compatible
// and not thread-safe though!)
class FsSpoolWriter {
 public:
  // The base, spool, and temporary directory will be created as needed on the
  // first call to Write() - however the base directory can be created into an
  // existing path (i.e. this class will not do an `mkdir -p`).
  FsSpoolWriter(absl::string_view base_dir, size_t max_spool_size);

  // Pushes the given byte array to the spool. The given maximum
  // spool size will be enforced. Returns an error code. If the spool gets full,
  // returns the UNAVAILABLE canonical code (which is retryable).
  absl::Status WriteMessage(absl::string_view msg);

  friend class fsspool::FsSpoolWriterPeer;

 private:
  const std::string base_dir_;
  const std::string spool_dir_;
  const std::string tmp_dir_;
  struct timespec spool_dir_last_mtime_;

  // Approximate maximum size of the spooling area, in bytes. If a message is
  // being written to a spooling area which already contains more than
  // maxSpoolSize bytes, the write will not be executed. This is an approximate
  // estimate: no care is taken to make an exact estimate (for example, if a
  // file gets deleted from the spool while the estimate is being computed, the
  // final estimate is likely to still include the size of that file).
  const size_t max_spool_size_;

  // 64bit hex ID for this writer. Used in combination with the sequence
  // number to generate unique names for files. This is generated through
  // util::random::NewGlobalID(), hence has only 52 bits of randomness.
  const std::string id_;

  // Sequence number of the next message to be written. This
  // counter will be incremented at every Write call, so that the produced
  // spooled files have different names.
  uint64_t sequence_number_ = 0;

  // Last estimate for the spool size. The estimate will grow every time we
  // write messages (basically, we compute it as if there was no reader
  // consuming messages). It will get updated with the actual value whenever we
  // think we've passed the size limit. The new estimate will be the sum of the
  // approximate disk space occupied by each message written (in multiples of
  // 4KiB, i.e. a typical disk cluster size).
  size_t spool_size_estimate_;

  // Makes sure that all the required
  // directories needed for correct operation of this Writer are present in the
  // filesystem.
  absl::Status BuildDirectoryStructureIfNeeded();

  // Generates a unique filename by combining the random ID of
  // this writer with a sequence number.
  std::string UniqueFilename();

  // Estimate the size of the spool directory. However, only recompute a new
  // estimate if the spool directory has has a change to its modification time.
  absl::StatusOr<size_t> EstimateSpoolDirSize();
};

// This class is thread-unsafe.
class FsSpoolReader {
 public:
  explicit FsSpoolReader(absl::string_view base_directory);
  absl::Status AckMessage(const std::string& message_path);
  // Returns absl::NotFoundError in case the FsSpool is empty.
  absl::StatusOr<std::string> NextMessagePath();
  int NumberOfUnackedMessages() const;

 private:
  const std::string base_dir_;
  const std::string spool_dir_;
  absl::flat_hash_set<std::string> unacked_messages_;

  absl::StatusOr<std::string> OldestSpooledFile();
};

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H_

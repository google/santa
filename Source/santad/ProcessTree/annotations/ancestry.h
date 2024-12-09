/// Copyright 2023 Google LLC
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
#ifndef SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_ANCESTRY_H
#define SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_ANCESTRY_H

#include <optional>

#include "Source/santad/ProcessTree/annotations/annotator.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"

namespace santa::santad::process_tree {

class AncestryAnnotator : public Annotator {
 public:
  // clang-format off
  AncestryAnnotator() {}
 explicit AncestryAnnotator(
            ::santa::pb::v1::process_tree::Annotations::Ancestry ancestry)
            : ancestry_(ancestry) {};
  // clang-format on
  void AnnotateFork(ProcessTree &tree, const Process &parent,
                    const Process &child) override;
  void AnnotateExec(ProcessTree &tree, const Process &orig_process,
                    const Process &new_process) override;
  std::optional<::santa::pb::v1::process_tree::Annotations> Proto()
      const override;
  ::santa::pb::v1::process_tree::Annotations::Ancestry getAncestry() const;

 private:
  void AddEntryToAncestry(
      ::santa::pb::v1::process_tree::Annotations::Ancestry &ancestry, int pid,
      uint64_t secondary_id);
  void CopyAncestorsToAncestry(
      ::santa::pb::v1::process_tree::Annotations::Ancestry &ancestry,
      std::vector<std::shared_ptr<const Process>> ancestors);
  ::santa::pb::v1::process_tree::Annotations::Ancestry ancestry_;
};

}  // namespace santa::santad::process_tree

#endif
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
#include "Source/santad/ProcessTree/annotations/originator.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "absl/container/flat_hash_map.h"

namespace ptpb = ::santa::pb::v1::process_tree;

namespace santa::santad::process_tree {

void OriginatorAnnotator::AnnotateFork(ProcessTree &tree, const Process &parent,
                                       const Process &child) {
  // "Base case". Propagate existing annotations down to descendants.
  if (auto annotation = tree.GetAnnotation<OriginatorAnnotator>(parent)) {
    tree.AnnotateProcess(child, std::move(*annotation));
  }
}

void OriginatorAnnotator::AnnotateExec(ProcessTree &tree,
                                       const Process &orig_process,
                                       const Process &new_process) {
  static const absl::flat_hash_map<std::string, ptpb::Annotations::Originator>
      originator_programs = {
          {"/usr/bin/login",
           ptpb::Annotations::Originator::Annotations_Originator_LOGIN},
          {"/usr/sbin/cron",
           ptpb::Annotations::Originator::Annotations_Originator_CRON},
      };

  if (auto annotation = tree.GetAnnotation<OriginatorAnnotator>(orig_process)) {
    tree.AnnotateProcess(new_process, std::move(*annotation));
    return;
  }

  if (auto it = originator_programs.find(new_process.program_->executable);
      it != originator_programs.end()) {
    tree.AnnotateProcess(new_process,
                         std::make_shared<OriginatorAnnotator>(it->second));
  }
}

std::optional<ptpb::Annotations> OriginatorAnnotator::Proto() const {
  auto annotation = ptpb::Annotations();
  annotation.set_originator(originator_);
  return annotation;
}

}  // namespace santa::santad::process_tree

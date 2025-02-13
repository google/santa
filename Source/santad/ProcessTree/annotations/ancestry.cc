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
#include "Source/santad/ProcessTree/annotations/ancestry.h"

#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "absl/container/flat_hash_map.h"

namespace ptpb = ::santa::pb::v1::process_tree;

namespace santa::santad::process_tree {

::santa::pb::v1::process_tree::Annotations::Ancestry
AncestryAnnotator::getAncestry() const {
  ::santa::pb::v1::process_tree::Annotations::Ancestry ancestry;
  ancestry.CopyFrom(ancestry_);
  return ancestry;
}

void AncestryAnnotator::AddEntryToAncestry(
    ptpb::Annotations::Ancestry &ancestry, int pid, uint64_t secondary_id) {
  ptpb::AncestryProcessID *ancestor = ancestry.add_ancestor();
  ancestor->set_pid(pid);
  ancestor->set_secondary_id(secondary_id);
}

void AncestryAnnotator::CopyAncestorsToAncestry(
    ptpb::Annotations::Ancestry &ancestry,
    std::vector<std::shared_ptr<const Process>> ancestors) {
  // Add ancestors starting from the root process
  for (auto it = ancestors.rbegin(); it != ancestors.rend(); it++) {
    AddEntryToAncestry(ancestry, (*it)->pid_.pid, (*it)->creation_timestamp);
  }
}

void AncestryAnnotator::AnnotateFork(ProcessTree &tree, const Process &parent,
                                     const Process &child) {
  ptpb::Annotations::Ancestry ancestry;
  // If parent process has ancestry annotation, copy and add parent.
  if (auto parent_annotation = tree.GetAnnotation<AncestryAnnotator>(parent)) {
    ancestry.CopyFrom((*parent_annotation)->getAncestry());
    AddEntryToAncestry(ancestry, parent.pid_.pid, parent.creation_timestamp);
    // Otherwise, get all ancestors of the child and add them.
  } else {
    std::vector<std::shared_ptr<const Process>> ancestors =
        tree.GetAncestors(child);
    CopyAncestorsToAncestry(ancestry, ancestors);
  }
  tree.AnnotateProcess(child, std::make_shared<AncestryAnnotator>(ancestry));
}

void AncestryAnnotator::AnnotateExec(ProcessTree &tree,
                                     const Process &orig_process,
                                     const Process &new_process) {
  ptpb::Annotations::Ancestry ancestry;
  // If original process has ancestry annotation, copy entries.
  if (auto orig_process_annotation =
          tree.GetAnnotation<AncestryAnnotator>(orig_process)) {
    ancestry.CopyFrom((*orig_process_annotation)->getAncestry());
    // Otherwise, compute all ancestors of the new process and add them.
  } else {
    std::vector<std::shared_ptr<const Process>> ancestors =
        tree.GetAncestors(new_process);
    CopyAncestorsToAncestry(ancestry, ancestors);
  }
  tree.AnnotateProcess(new_process,
                       std::make_shared<AncestryAnnotator>(ancestry));
}

std::optional<ptpb::Annotations> AncestryAnnotator::Proto() const {
  auto annotation = ptpb::Annotations();
  auto *ancestry_ptr = annotation.mutable_ancestry();
  ancestry_ptr->CopyFrom(AncestryAnnotator::getAncestry());
  return annotation;
}

}  // namespace santa::santad::process_tree
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
#ifndef SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_ORIGINATOR_H
#define SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_ORIGINATOR_H

#include <optional>

#include "Source/santad/ProcessTree/annotations/annotator.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"

namespace santa::santad::process_tree {

class OriginatorAnnotator : public Annotator {
 public:
  OriginatorAnnotator()
      : originator_(::santa::pb::v1::process_tree::Annotations::Originator::
                        Annotations_Originator_UNSPECIFIED) {};
  explicit OriginatorAnnotator(
      ::santa::pb::v1::process_tree::Annotations::Originator originator)
      : originator_(originator) {};

  void AnnotateFork(ProcessTree &tree, const Process &parent,
                    const Process &child) override;
  void AnnotateExec(ProcessTree &tree, const Process &orig_process,
                    const Process &new_process) override;

  std::optional<::santa::pb::v1::process_tree::Annotations> Proto()
      const override;

 private:
  ::santa::pb::v1::process_tree::Annotations::Originator originator_;
};

}  // namespace santa::santad::process_tree

#endif

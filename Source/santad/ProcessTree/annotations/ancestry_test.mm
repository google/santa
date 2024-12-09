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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include "Source/santad/ProcessTree/annotations/ancestry.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "Source/santad/ProcessTree/process_tree_test_helpers.h"

using namespace santa::santad::process_tree;
namespace ptpb = ::santa::pb::v1::process_tree;

@interface AncestryAnnotatorTest : XCTestCase
@property std::shared_ptr<ProcessTreeTestPeer> tree;
@property std::shared_ptr<const Process> initProc;
@end

@implementation AncestryAnnotatorTest

- (void)setUp {
  std::vector<std::unique_ptr<Annotator>> annotators;
  annotators.emplace_back(std::make_unique<AncestryAnnotator>());
  self.tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  self.initProc = self.tree->InsertInit();
}

- (void)testSingleFork_childHasAncestryAnnotation {
  // PID 1.1: fork() -> PID 1.1
  //                 -> PID 2.2
  uint64_t event_id = 123;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, child_pid);

  auto child = *self.tree->Get(child_pid);
  auto annotation_opt = self.tree->GetAnnotation<AncestryAnnotator>(*child);
  XCTAssertTrue(annotation_opt.has_value());
  auto proto_opt = (*annotation_opt)->Proto();

  XCTAssertTrue(proto_opt.has_value());
  XCTAssertEqual(proto_opt->ancestry().ancestor_size(), 1);
  XCTAssertEqual(proto_opt->ancestry().ancestor().Get(0).pid(), 1);
  XCTAssertEqual(proto_opt->ancestry().ancestor().Get(0).secondary_id(), 0);
}

- (void)testDoubleFork_grandchildHasAncestryAnnotation {
  // PID 1.1: fork() -> PID 1.1
  //                 -> PID 2.2 fork() -> PID 2.2
  //                                   -> PID 3.3
  uint64_t event_id = 123;
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  const struct Pid grandchild_pid = {.pid = 3, .pidversion = 3};

  self.tree->HandleFork(event_id++, *self.initProc, child_pid);
  auto child = *self.tree->Get(child_pid);
  self.tree->HandleFork(event_id++, *child, grandchild_pid);

  auto grandchild = *self.tree->Get(grandchild_pid);
  auto annotation_opt = self.tree->GetAnnotation<AncestryAnnotator>(*grandchild);
  XCTAssertTrue(annotation_opt.has_value());
  auto grandchild_proto_opt = (*annotation_opt)->Proto();
  XCTAssertTrue(grandchild_proto_opt.has_value());
  auto grandchild_proto = *grandchild_proto_opt;
  XCTAssertEqual(grandchild_proto.ancestry().ancestor_size(), 2);
  XCTAssertEqual(grandchild_proto.ancestry().ancestor().Get(0).pid(), 1);
  XCTAssertEqual(grandchild_proto.ancestry().ancestor().Get(0).secondary_id(), 0);
  XCTAssertEqual(grandchild_proto.ancestry().ancestor().Get(1).pid(), 2);
  XCTAssertEqual(grandchild_proto.ancestry().ancestor().Get(1).secondary_id(), 123);
}

- (void)testRootProcessExec_processAfterExecStillHasNoAncestors {
  // PID 1.1: exec() -> PID 1.2
  uint64_t event_id = 123;
  const struct Cred cred = {.uid = 0, .gid = 0};
  const struct Pid pid_after_exec = {.pid = 1, .pidversion = 2};
  const struct Program program = {.executable = "/any/executable", .arguments = {}};

  self.tree->HandleExec(event_id++, *self.initProc, pid_after_exec, program, cred);

  auto process_after_exec = *self.tree->Get(pid_after_exec);
  auto annotation_opt = self.tree->GetAnnotation<AncestryAnnotator>(*process_after_exec);
  XCTAssertTrue(annotation_opt.has_value());
  auto proto_opt = (*annotation_opt)->Proto();
  XCTAssertTrue(proto_opt.has_value());
  auto proto = *proto_opt;
  XCTAssertEqual(proto.ancestry().ancestor_size(), 0);
}

- (void)testForkAndExec_processAfterExecHasTheSameAnnotation {
  // PID 1.1: fork() -> PID 1.1
  //                 -> PID 2.2 exec() -> PID 2.3
  uint64_t event_id = 123;
  const struct Cred cred = {.uid = 0, .gid = 0};
  const struct Pid child_pid = {.pid = 2, .pidversion = 2};
  const struct Pid child_pid_after_exec = {.pid = 2, .pidversion = 3};
  const struct Program program = {.executable = "/any/executable", .arguments = {}};

  self.tree->HandleFork(event_id++, *self.initProc, child_pid);
  auto child = *self.tree->Get(child_pid);
  self.tree->HandleExec(event_id++, *child, child_pid_after_exec, program, cred);

  auto child_after_exec = *self.tree->Get(child_pid_after_exec);
  auto annotation_opt = self.tree->GetAnnotation<AncestryAnnotator>(*child_after_exec);
  XCTAssertTrue(annotation_opt.has_value());
  auto proto_opt = (*annotation_opt)->Proto();
  XCTAssertTrue(proto_opt.has_value());
  auto proto = *proto_opt;
  XCTAssertEqual(proto.ancestry().ancestor_size(), 1);
  XCTAssertEqual(proto.ancestry().ancestor().Get(0).pid(), 1);
  XCTAssertEqual(proto.ancestry().ancestor().Get(0).secondary_id(), 0);
}

- (void)testForkAndParentExit_childHasOriginalAncestryAfterParentExit {
  // PID 1.1: fork() -> PID 1.1
  //                 -> PID 2.2 fork() -> PID 2.2 exit()
  //                                   -> PID 3.3
  uint64_t event_id = 123;
  const struct Pid parent_pid = {.pid = 2, .pidversion = 2};
  const struct Pid child_pid = {.pid = 3, .pidversion = 3};

  // Double fork to not call exit on the root process
  self.tree->HandleFork(event_id++, *self.initProc, parent_pid);
  auto parent = *self.tree->Get(parent_pid);
  self.tree->HandleFork(event_id++, *parent, child_pid);
  auto child = *self.tree->Get(child_pid);
  self.tree->HandleExit(event_id++, *parent);

  auto annotation_opt = self.tree->GetAnnotation<AncestryAnnotator>(*child);
  XCTAssertTrue(annotation_opt.has_value());
  auto proto_opt = (*annotation_opt)->Proto();
  XCTAssertTrue(proto_opt.has_value());
  auto proto = *proto_opt;
  XCTAssertEqual(proto.ancestry().ancestor_size(), 2);
  XCTAssertEqual(proto.ancestry().ancestor().Get(0).pid(), 1);
  XCTAssertEqual(proto.ancestry().ancestor().Get(0).secondary_id(), 0);
  XCTAssertEqual(proto.ancestry().ancestor().Get(1).pid(), 2);
  XCTAssertEqual(proto.ancestry().ancestor().Get(1).secondary_id(), 123);
}

- (void)testBackfillInsertChildren_processesHaveAnnotation {
  /*
          PID 1.1
          /     \
      PID 2.2   PID 3.3
                  /
              PID 4.4
  */
  const struct Cred cred = {.uid = 0, .gid = 0};
  const struct Program program = {.executable = "/any/executable", .arguments = {}};
  absl::flat_hash_map<pid_t, std::vector<Process>> parent_map;
  Process p1 =  // root
    Process({.pid = 1, .pidversion = 1}, cred, std::make_shared<Program>(program), nullptr, 0);
  Process p2 =
    Process({.pid = 2, .pidversion = 2}, cred, std::make_shared<Program>(program), nullptr, 0);
  Process p3 =
    Process({.pid = 3, .pidversion = 3}, cred, std::make_shared<Program>(program), nullptr, 0);
  Process p4 =
    Process({.pid = 4, .pidversion = 4}, cred, std::make_shared<Program>(program), nullptr, 0);
  parent_map[1].push_back(p2);
  parent_map[1].push_back(p3);
  parent_map[3].push_back(p4);
  std::vector<std::unique_ptr<Annotator>> annotators;
  annotators.emplace_back(std::make_unique<AncestryAnnotator>());
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));

  tree->BackfillInsertChildren(parent_map, std::shared_ptr<Process>(), p1);

  auto p4_from_tree = *tree->Get(p4.pid_);
  auto annotation_opt = tree->GetAnnotation<AncestryAnnotator>(*p4_from_tree);
  XCTAssertTrue(annotation_opt.has_value());
  auto proto_opt = (*annotation_opt)->Proto();
  XCTAssertTrue(proto_opt.has_value());
  auto proto = *proto_opt;
  XCTAssertEqual(proto.ancestry().ancestor_size(), 2);
  XCTAssertEqual(proto.ancestry().ancestor().Get(0).pid(), 1);
  XCTAssertEqual(proto.ancestry().ancestor().Get(0).secondary_id(), 0);
  XCTAssertEqual(proto.ancestry().ancestor().Get(1).pid(), 3);
  XCTAssertEqual(proto.ancestry().ancestor().Get(1).secondary_id(), 0);
}

@end
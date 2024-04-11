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

#include "Source/santad/ProcessTree/annotations/originator.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "Source/santad/ProcessTree/process_tree_test_helpers.h"

using namespace santa::santad::process_tree;
namespace ptpb = ::santa::pb::v1::process_tree;

@interface OriginatorAnnotatorTest : XCTestCase
@property std::shared_ptr<ProcessTreeTestPeer> tree;
@property std::shared_ptr<const Process> initProc;
@end

@implementation OriginatorAnnotatorTest

- (void)setUp {
  std::vector<std::unique_ptr<Annotator>> annotators;
  annotators.emplace_back(std::make_unique<OriginatorAnnotator>());
  self.tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  self.initProc = self.tree->InsertInit();
}

- (void)testAnnotation {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  // PID 1.1: fork() -> PID 2.2
  const struct Pid login_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, login_pid);

  // PID 2.2: exec("/usr/bin/login") -> PID 2.3
  const struct Pid login_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program login_prog = {.executable = "/usr/bin/login", .arguments = {}};
  auto login = *self.tree->Get(login_pid);
  self.tree->HandleExec(event_id++, *login, login_exec_pid, login_prog, cred);

  // Ensure we have an annotation on login itself...
  login = *self.tree->Get(login_exec_pid);
  auto annotation_opt = self.tree->GetAnnotation<OriginatorAnnotator>(*login);
  XCTAssertTrue(annotation_opt.has_value());
  auto proto_opt = (*annotation_opt)->Proto();
  XCTAssertTrue(proto_opt.has_value());
  XCTAssertEqual(proto_opt->originator(),
                 ptpb::Annotations::Originator::Annotations_Originator_LOGIN);

  // PID 2.3: fork() -> PID 3.3
  const struct Pid shell_pid = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(event_id++, *login, shell_pid);
  // PID 3.3: exec("/bin/zsh") -> PID 3.4
  const struct Pid shell_exec_pid = {.pid = 3, .pidversion = 4};
  const struct Program shell_prog = {.executable = "/bin/zsh", .arguments = {}};
  auto shell = *self.tree->Get(shell_pid);
  self.tree->HandleExec(event_id++, *shell, shell_exec_pid, shell_prog, cred);

  // ... and also ensure we have the same annotation on the descendant zsh.
  shell = *self.tree->Get(shell_exec_pid);
  auto descendant_annotation_opt = self.tree->GetAnnotation<OriginatorAnnotator>(*shell);
  XCTAssertTrue(descendant_annotation_opt.has_value());
  XCTAssertEqual(*descendant_annotation_opt, *annotation_opt);
}

@end

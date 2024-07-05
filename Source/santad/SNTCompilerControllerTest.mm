/// Copyright 2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#include "Source/santad/SNTCompilerController.h"

#include <EndpointSecurity/EndpointSecurity.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/stat.h>

#include <memory>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTFileInfo.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTDecisionCache.h"

using santa::Logger;
using santa::santad::event_providers::endpoint_security::Message;

static const pid_t PID_MAX = 99999;

@interface SNTCompilerController (Testing)
- (BOOL)isCompiler:(const audit_token_t &)tok;
- (void)saveFakeDecision:(SNTFileInfo *)esFile;
- (void)removeFakeDecision:(SNTFileInfo *)esFile;
- (void)createTransitiveRule:(const Message &)esMsg
                      target:(SNTFileInfo *)targetFile
                      logger:(std::shared_ptr<Logger>)logger;
@end

@interface SNTCompilerControllerTest : XCTestCase
@property id mockDecisionCache;
@property audit_token_t tok1;
@property audit_token_t tok2;
@property audit_token_t tokNegativePid;
@property audit_token_t tokLargePid;
@end

@implementation SNTCompilerControllerTest

- (void)setUp {
  self.mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);

  self.tok1 = MakeAuditToken(12, 11);
  self.tok2 = MakeAuditToken(34, 22);
  self.tokNegativePid = MakeAuditToken(-1, 33);
  self.tokLargePid = MakeAuditToken(PID_MAX + 1, 44);
}

- (void)tearDown {
  [self.mockDecisionCache stopMocking];
}

- (void)testIsCompiler {
  SNTCompilerController *cc = [[SNTCompilerController alloc] init];

  // Ensure invalid PIDs are handled
  XCTAssertFalse([cc isCompiler:self.tokNegativePid]);
  XCTAssertFalse([cc isCompiler:self.tokLargePid]);

  // Items in the compiler control cache are initially false
  XCTAssertFalse([cc isCompiler:self.tok1]);

  // Start tracking a process as a compiler
  [cc setProcess:self.tok1 isCompiler:true];
  XCTAssertTrue([cc isCompiler:self.tok1]);

  // Stop tracking a process as a compiler
  [cc setProcess:self.tok1 isCompiler:false];
  XCTAssertFalse([cc isCompiler:self.tok1]);
}

- (void)testSetProcessIsCompiler {
  SNTCompilerController *cc = [[SNTCompilerController alloc] init];

  // Ensure invalid PIDs are handled
  XCTAssertNoThrow([cc setProcess:self.tokNegativePid isCompiler:true]);
  XCTAssertNoThrow([cc setProcess:self.tokLargePid isCompiler:true]);

  // Ensure test tokens are initially false
  XCTAssertFalse([cc isCompiler:self.tok1]);
  XCTAssertFalse([cc isCompiler:self.tok2]);

  // Start tracking one of the toks
  [cc setProcess:self.tok1 isCompiler:true];
  XCTAssertTrue([cc isCompiler:self.tok1]);
  XCTAssertFalse([cc isCompiler:self.tok2]);

  // Start tracking both toks
  [cc setProcess:self.tok2 isCompiler:true];
  XCTAssertTrue([cc isCompiler:self.tok1]);
  XCTAssertTrue([cc isCompiler:self.tok2]);

  // Stop tracking one of the toks
  [cc setProcess:self.tok1 isCompiler:false];
  XCTAssertFalse([cc isCompiler:self.tok1]);
  XCTAssertTrue([cc isCompiler:self.tok2]);
}

- (void)testSaveFakeDecision {
  SantaVnode vnode{
    .fsid = 12,
    .fileid = 34,
  };

  OCMExpect([self.mockDecisionCache
    cacheDecision:[OCMArg checkWithBlock:^BOOL(SNTCachedDecision *cd) {
      return cd.vnodeId == vnode && cd.decision == SNTEventStateAllowPendingTransitive &&
             [cd.sha256 isEqualToString:@"pending"];
    }]]);

  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMExpect([mockFileInfo vnode]).andReturn(vnode);

  SNTCompilerController *cc = [[SNTCompilerController alloc] init];
  [cc saveFakeDecision:mockFileInfo];

  XCTAssertTrue(OCMVerifyAll(self.mockDecisionCache), "Unable to verify all expectations");
}

- (void)testRemoveFakeDecision {
  SantaVnode vnode{
    .fsid = 12,
    .fileid = 34,
  };

  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMExpect([mockFileInfo vnode]).andReturn(vnode);

  OCMExpect([self.mockDecisionCache forgetCachedDecisionForVnode:vnode]);

  SNTCompilerController *cc = [[SNTCompilerController alloc] init];
  [cc removeFakeDecision:mockFileInfo];

  XCTAssertTrue(OCMVerifyAll(self.mockDecisionCache), "Unable to verify all expectations");
}

- (void)testHandleEventWithLogger {
  es_file_t file = MakeESFile("foo");
  es_file_t ignoredFile = MakeESFile("/dev/bar");
  es_file_t normalFile = MakeESFile("bar");
  SantaVnode vnodeNormal = SantaVnode::VnodeForFile(&normalFile);
  audit_token_t compilerTok = MakeAuditToken(12, 34);
  audit_token_t notCompilerTok = MakeAuditToken(56, 78);
  es_process_t compilerProc = MakeESProcess(&file, compilerTok, {});
  es_process_t notCompilerProc = MakeESProcess(&file, notCompilerTok, {});
  es_message_t esMsg;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  SNTCompilerController *cc = [[SNTCompilerController alloc] init];

  // Mark a process as a compiler for use with these tests.
  [cc setProcess:compilerTok isCompiler:true];

  // Ensure unhandled event types return appropriately
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_FORK, &notCompilerProc);
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }

  // Ensure non-compiler process events return false
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &notCompilerProc);
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &notCompilerProc);
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }

  // Ensure compiler process events are only handled with non-ignored paths
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &compilerProc);
    esMsg.event.close.target = &ignoredFile;
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &compilerProc);
    esMsg.event.rename.source = &ignoredFile;
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([cc handleEvent:msg withLogger:nullptr]);
  }

  // Ensure EXIT events stop tracking the process as a compiler
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &compilerProc);
    Message msg(mockESApi, &esMsg);

    id mockCompilerController = OCMPartialMock(cc);
    OCMExpect([mockCompilerController setProcess:compilerProc.audit_token isCompiler:false]);

    XCTAssertTrue([cc handleEvent:msg withLogger:nullptr]);

    XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
    [mockCompilerController stopMocking];
  }

  // Ensure transitive rules are created when the given event is handled
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &compilerProc);
    esMsg.event.close.target = &normalFile;
    Message msg(mockESApi, &esMsg);

    id mockCompilerController = OCMPartialMock(cc);
    id mockFileInfo = OCMClassMock([SNTFileInfo class]);
    OCMStub([mockFileInfo alloc]).andReturn(mockFileInfo);
    OCMStub([mockFileInfo initWithEndpointSecurityFile:&normalFile error:[OCMArg anyObjectRef]])
      .ignoringNonObjectArgs()
      .andReturn(mockFileInfo);
    OCMStub([mockFileInfo vnode]).andReturn(vnodeNormal);

    OCMExpect([mockCompilerController
                createTransitiveRule:msg
                              target:[OCMArg checkWithBlock:^BOOL(SNTFileInfo *fi) {
                                return fi.vnode.fsid == normalFile.stat.st_dev &&
                                       fi.vnode.fileid == normalFile.stat.st_ino;
                              }]
                              logger:nullptr])
      .ignoringNonObjectArgs();

    XCTAssertTrue([cc handleEvent:msg withLogger:nullptr]);

    XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
    [mockCompilerController stopMocking];
    [mockFileInfo stopMocking];
  }
  // Ensure transitive rules are created for RENAME events from the source path
  {
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &compilerProc);
    esMsg.event.rename.source = &normalFile;
    Message msg(mockESApi, &esMsg);

    id mockCompilerController = OCMPartialMock(cc);
    id mockFileInfo = OCMClassMock([SNTFileInfo class]);
    OCMStub([mockFileInfo alloc]).andReturn(mockFileInfo);
    OCMStub([mockFileInfo initWithEndpointSecurityFile:&normalFile error:[OCMArg anyObjectRef]])
      .ignoringNonObjectArgs()
      .andReturn(mockFileInfo);
    OCMStub([mockFileInfo vnode]).andReturn(vnodeNormal);

    OCMExpect([mockCompilerController
                createTransitiveRule:msg
                              target:[OCMArg checkWithBlock:^BOOL(SNTFileInfo *fi) {
                                return fi.vnode.fsid == normalFile.stat.st_dev &&
                                       fi.vnode.fileid == normalFile.stat.st_ino;
                              }]
                              logger:nullptr])
      .ignoringNonObjectArgs();

    XCTAssertTrue([cc handleEvent:msg withLogger:nullptr]);

    XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
    [mockCompilerController stopMocking];
    [mockFileInfo stopMocking];
  }
  // Ensure transitive rules are created for RENAME events from the existing destinatio path as a
  // fallback
  {
    es_file_t destFile = MakeESFile("dest", MakeStat(1000));
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &compilerProc);
    esMsg.event.rename.source = &normalFile;
    esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
    esMsg.event.rename.destination.existing_file = &destFile;
    Message msg(mockESApi, &esMsg);
    SantaVnode vnodeDest = SantaVnode::VnodeForFile(&destFile);

    id mockCompilerController = OCMPartialMock(cc);
    id mockFileInfo = OCMClassMock([SNTFileInfo class]);
    OCMStub([mockFileInfo alloc]).andReturn(mockFileInfo);
    // Return nil the first time when the source path is looked up
    OCMExpect([mockFileInfo initWithEndpointSecurityFile:&normalFile error:[OCMArg anyObjectRef]])
      .ignoringNonObjectArgs()
      .andReturn(nil);
    OCMExpect([mockFileInfo initWithEndpointSecurityFile:&destFile error:[OCMArg anyObjectRef]])
      .ignoringNonObjectArgs()
      .andReturn(mockFileInfo);
    OCMStub([mockFileInfo vnode]).andReturn(vnodeDest);

    OCMExpect([mockCompilerController
                createTransitiveRule:msg
                              target:[OCMArg checkWithBlock:^BOOL(SNTFileInfo *fi) {
                                return fi.vnode.fsid == destFile.stat.st_dev &&
                                       fi.vnode.fileid == destFile.stat.st_ino;
                              }]
                              logger:nullptr])
      .ignoringNonObjectArgs();

    XCTAssertTrue([cc handleEvent:msg withLogger:nullptr]);

    XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
    [mockCompilerController stopMocking];
    [mockFileInfo stopMocking];
  }
  // Ensure transitive rules are created for RENAME events from the existing destinatio path as a
  // fallback
  {
    es_file_t destDir = MakeESFile("/usr/bin", MakeStat(1000));
    es_string_token_t destFilename = MakeESStringToken("true");
    esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &compilerProc);
    esMsg.event.rename.source = &normalFile;
    esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
    esMsg.event.rename.destination.new_path.dir = &destDir;
    esMsg.event.rename.destination.new_path.filename = destFilename;
    Message msg(mockESApi, &esMsg);
    NSString *expectedTarget =
      [NSString stringWithFormat:@"%s/%s", destDir.path.data, destFilename.data];

    struct stat sbNewFile;
    XCTAssertEqual(stat("/usr/bin/true", &sbNewFile), 0);
    SantaVnode vnodeDest = SantaVnode::VnodeForFile(sbNewFile);

    id mockCompilerController = OCMPartialMock(cc);
    id mockFileInfo = OCMClassMock([SNTFileInfo class]);
    OCMStub([mockFileInfo alloc]).andReturn(mockFileInfo);
    OCMStub([mockFileInfo vnode]).andReturn(vnodeDest);

    // Return nil the first time when the source path is looked up
    OCMExpect([mockFileInfo initWithEndpointSecurityFile:&normalFile error:[OCMArg anyObjectRef]])
      .ignoringNonObjectArgs()
      .andReturn(nil);
    OCMExpect([mockFileInfo initWithPath:expectedTarget error:[OCMArg anyObjectRef]])
      .ignoringNonObjectArgs()
      .andReturn(mockFileInfo);

    OCMExpect([mockCompilerController
                createTransitiveRule:msg
                              target:[OCMArg checkWithBlock:^BOOL(SNTFileInfo *fi) {
                                return fi.vnode.fsid == sbNewFile.st_dev &&
                                       fi.vnode.fileid == sbNewFile.st_ino;
                              }]
                              logger:nullptr])
      .ignoringNonObjectArgs();

    XCTAssertTrue([cc handleEvent:msg withLogger:nullptr]);

    XCTAssertTrue(OCMVerifyAll(mockCompilerController), "Unable to verify all expectations");
    [mockCompilerController stopMocking];
    [mockFileInfo stopMocking];
  }
}

@end

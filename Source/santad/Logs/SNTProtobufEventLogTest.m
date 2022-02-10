/// Copyright 2021 Google Inc. All rights reserved.
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

#import <EndpointSecurity/EndpointSecurity.h>

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import <grp.h>
#import <pwd.h>

#import "Source/common/SNTAllowlistInfo.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/santad/EventProviders/EndpointSecurityTestUtil.h"
#import "Source/santad/Logs/SNTProtobufEventLog.h"
#import "Source/santad/Logs/SNTSimpleMaildir.h"

@interface SNTProtobufEventLogTest : XCTestCase
@property id mockConfigurator;
@property id mockLogOutput;
@end

@interface SNTProtobufEventLog (Testing)
- (instancetype)initWithLog:(id<SNTLogOutput>)log;
@end

NSString *getBestBundleName(NSBundle *bundle) {
  NSDictionary *infoDict = [bundle infoDictionary];
  return [[infoDict objectForKey:@"CFBundleDisplayName"] description]
           ?: [[infoDict objectForKey:@"CFBundleName"] description];
}

SNTStoredEvent *createTestBundleStoredEvent(NSBundle *bundle, NSString *fakeBundleHash,
                                            NSString *fakeFileHash) {
  if (!bundle) {
    return nil;
  }

  SNTStoredEvent *event = [[SNTStoredEvent alloc] init];

  event.idx = @(arc4random());
  event.fileSHA256 = fakeFileHash;
  event.fileBundleHash = fakeBundleHash;
  event.fileBundleName = getBestBundleName(bundle);
  event.fileBundleID = bundle.bundleIdentifier;
  event.filePath = bundle.executablePath;
  event.fileBundlePath = bundle.bundlePath;

  return event;
}

id getEventForMessage(SNTSantaMessage *santaMsg,
                      SNTLegacyMessage_LegacyMessageType_OneOfCase expectedCase,
                      NSString *propertyName, Class expectedClass) {
  if (santaMsg.messageTypeOneOfCase != SNTSantaMessage_MessageType_OneOfCase_LegacyMessage) {
    LOGE(@"Unexpected santa message type");
    return nil;
  }

  SNTLegacyMessage *smLegacyMsg = santaMsg.legacyMessage;
  if (smLegacyMsg.legacyMessageTypeOneOfCase != expectedCase) {
    LOGE(@"Unexpected legacy message type. Had: %d, Expected: %d",
         smLegacyMsg.legacyMessageTypeOneOfCase, expectedCase);
    return nil;
  }

  id event = [smLegacyMsg valueForKey:propertyName];
  XCTAssertTrue([event isKindOfClass:expectedClass], "Extracted unexpected class");

  return event;
}

NSBundle *getBundleForSystemApplication(NSString *appName) {
  if (@available(macOS 10.15, *)) {
    return
      [NSBundle bundleWithPath:[NSString stringWithFormat:@"/System/Applications/%@", appName]];
  } else {
    return [NSBundle bundleWithPath:[NSString stringWithFormat:@"/Applications/%@", appName]];
  }
}

void assertProcessInfoMatchesExpected(SNTLegacyProcessInfo *procInfo,
                                      const santa_message_t *expected) {
  NSLog(@"p: %d/%d, pv: %d/%d, pp: %d/%d, u: %d/%d, g: %d/%d, un: %@/%@, gn: %@/%@", procInfo.pid,
        expected->pid, procInfo.pidversion, expected->pidversion, procInfo.ppid, expected->ppid,
        procInfo.uid, expected->uid, procInfo.gid, expected->gid, procInfo.user,
        @(user_from_uid(expected->uid, 0)), procInfo.group, @(group_from_gid(expected->gid, 0)));
  XCTAssertTrue(procInfo.pid == expected->pid && procInfo.pidversion == expected->pidversion &&
                  procInfo.ppid == expected->ppid && procInfo.uid == expected->uid &&
                  procInfo.gid == expected->gid &&
                  [procInfo.user isEqualToString:@(user_from_uid(expected->uid, 0))] &&
                  [procInfo.group isEqualToString:@(group_from_gid(expected->gid, 0))],
                "Unexpected process info encountered");
}

// Creates a basic santa message with only process-related info filled out.
// Adding path data is left as an exercise to the caller.
santa_message_t getBasicSantaMessage(santa_action_t action) {
  santa_message_t santaMsg = {0};

  santaMsg.action = action;
  santaMsg.uid = 242;
  santaMsg.gid = 20;
  santaMsg.pid = arc4random() % 1000;
  santaMsg.pidversion = arc4random() % 1000;
  santaMsg.ppid = arc4random() % 1000;

  return santaMsg;
}

@implementation SNTProtobufEventLogTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableMachineIDDecoration]).andReturn(NO);

  self.mockLogOutput = OCMStrictProtocolMock(@protocol(SNTLogOutput));
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
  [self.mockLogOutput stopMocking];
}

- (void)testLogFileModification {
  NSString *processName = @"launchd";
  NSString *processPath = @"/sbin/launchd";
  NSString *sourcePath = @"/foo/bar.txt";
  NSString *targetPath = @"/bar/foo.txt";

  // Create a test ES message with some important data set
  es_file_t esFile = MakeESFile([processPath UTF8String]);
  es_process_t esProc = MakeESProcess(&esFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_RENAME, &esProc);

  santa_message_t santaMsg = getBasicSantaMessage(ACTION_NOTIFY_RENAME);
  strlcpy(santaMsg.path, [sourcePath UTF8String], sizeof(santaMsg.path));
  strlcpy(santaMsg.newpath, [targetPath UTF8String], sizeof(santaMsg.newpath));
  strlcpy(santaMsg.pname, [processName UTF8String], sizeof(santaMsg.pname));
  santaMsg.args_array = nil;
  santaMsg.es_message = &esMsg;

  OCMExpect([self.mockLogOutput
    logEvent:[OCMArg checkWithBlock:^BOOL(SNTSantaMessage *sm) {
      SNTLegacyFileModification *fileMod =
        getEventForMessage(sm, SNTLegacyMessage_LegacyMessageType_OneOfCase_FileModification,
                           @"fileModification", [SNTLegacyFileModification class]);

      if (fileMod.action != SNTLegacyFileModification_Action_LegacyFileModificationActionRename ||
          ![fileMod.path isEqualToString:sourcePath] ||
          ![fileMod.newpath isEqualToString:targetPath] ||
          ![fileMod.process isEqualToString:processName] ||
          ![fileMod.processPath isEqualToString:processPath] || !fileMod.hasProcessInfo ||
          fileMod.processInfo == nil || [fileMod.machineId length] != 0) {
        LOGE(@"Unexpected file modification data");
        return NO;
      }

      assertProcessInfoMatchesExpected(fileMod.processInfo, &santaMsg);

      return YES;
    }]]);

  SNTProtobufEventLog *eventLog = [[SNTProtobufEventLog alloc] initWithLog:self.mockLogOutput];
  [eventLog logFileModification:santaMsg];

  XCTAssertTrue(OCMVerifyAll(self.mockLogOutput), "Unable to verify all expectations");
}

- (void)testLogExecutionDenied {
  NSString *processName = @"launchd";
  NSString *processPath = @"/sbin/launchd";
  NSArray *execArgs = @[ @"/sbin/launchd", @"--init", @"--testing" ];
  NSString *explanation = @"explanation";
  NSString *sha256 = @"a4587ab1e705a3804fd23c387a7bc1b39505f699eca35f57687809f8a7031d0f";
  NSString *certSHA256 = @"293d4a40b539dfddf9e011fb0e37f19aa86c96aad2e4bf481aac9e50487f3868";
  NSString *commonName = @"my cert common name";
  NSString *quarantineURL = @"http://localhost/quarantine";

  santa_message_t santaMsg = getBasicSantaMessage(ACTION_NOTIFY_EXEC);
  strlcpy(santaMsg.path, [processPath UTF8String], sizeof(santaMsg.path));
  santaMsg.newpath[0] = '\0';
  strlcpy(santaMsg.pname, [processName UTF8String], sizeof(santaMsg.pname));
  santaMsg.args_array = (__bridge void *)execArgs;
  santaMsg.es_message = nil;

  SNTCachedDecision *cachedDecision = [[SNTCachedDecision alloc] init];
  cachedDecision.decision = SNTEventStateBlockTeamID;
  cachedDecision.decisionExtra = explanation;
  cachedDecision.sha256 = sha256;
  cachedDecision.certSHA256 = certSHA256;
  cachedDecision.certCommonName = commonName;
  cachedDecision.quarantineURL = quarantineURL;

  OCMExpect([self.mockLogOutput
    logEvent:[OCMArg checkWithBlock:^BOOL(SNTSantaMessage *sm) {
      SNTLegacyExecution *exec =
        getEventForMessage(sm, SNTLegacyMessage_LegacyMessageType_OneOfCase_Execution, @"execution",
                           [SNTLegacyExecution class]);

      if (exec.decision != SNTLegacyExecution_Decision_LegacyExecutionDecisionDeny ||
          exec.reason != SNTLegacyExecution_Reason_LegacyExecutionReasonTeamId ||
          ![exec.explain isEqualToString:explanation] || ![exec.sha256 isEqualToString:sha256] ||
          ![exec.certSha256 isEqualToString:certSHA256] ||
          ![exec.certCn isEqualToString:commonName] ||
          ![exec.quarantineURL isEqualToString:quarantineURL] || !exec.hasProcessInfo ||
          exec.processInfo == nil ||
          exec.mode != SNTLegacyExecution_Mode_LegacyExecutionModeLockdown ||
          ![exec.path isEqualToString:processPath] || [exec.originalPath length] != 0 ||
          ![exec.argsArray isEqualToArray:execArgs] || [exec.machineId length] != 0) {
        LOGE(@"Unexpected execution data");
        return NO;
      }

      assertProcessInfoMatchesExpected(exec.processInfo, &santaMsg);

      return YES;
    }]]);

  SNTProtobufEventLog *eventLog = [[SNTProtobufEventLog alloc] initWithLog:self.mockLogOutput];
  [eventLog logDeniedExecution:cachedDecision withMessage:santaMsg];

  XCTAssertTrue(OCMVerifyAll(self.mockLogOutput), "Unable to verify all expectations");
}

- (void)testLogDiskAppeared {
  NSString *mount = @"/mnt/appear";
  NSString *volume = @"Macintosh HD";
  NSString *bsdName = @"disk0s1";
  NSString *kind = @"apfs";
  NSString *deviceVendor = @"gCorp";
  NSString *deviceModel = @"G1";
  NSString *serial = @"fake_serial";
  NSString *devicePath = @"IODeviceTree:/";
  NSString *deviceProto = @"USB";
  NSString *appeared = @"2001-01-01T00:00:00.000Z";

  NSDictionary *diskProperties = @{
    @"DAVolumePath" : [NSURL URLWithString:mount],
    @"DAVolumeName" : volume,
    @"DAMediaBSDName" : bsdName,
    @"DAVolumeKind" : kind,
    @"DADeviceVendor" : deviceVendor,
    @"DADeviceModel" : deviceModel,
    @"DADevicePath" : devicePath,
    @"DADeviceProtocol" : deviceProto,
  };

  OCMExpect([self.mockLogOutput
    logEvent:[OCMArg checkWithBlock:^BOOL(SNTSantaMessage *sm) {
      SNTLegacyDiskAppeared *diskAppeared =
        getEventForMessage(sm, SNTLegacyMessage_LegacyMessageType_OneOfCase_DiskAppeared,
                           @"diskAppeared", [SNTLegacyDiskAppeared class]);

      if (![diskAppeared.mount isEqualToString:mount] ||
          ![diskAppeared.volume isEqualToString:volume] ||
          ![diskAppeared.bsdName isEqualToString:bsdName] ||
          ![diskAppeared.fs isEqualToString:kind] ||
          ![diskAppeared.model
            isEqualToString:[NSString stringWithFormat:@"%@ %@", deviceVendor, deviceModel]] ||
          ![diskAppeared.serial isEqualToString:serial] ||
          ![diskAppeared.bus isEqualToString:deviceProto] || [diskAppeared.dmgPath length] != 0 ||
          ![diskAppeared.appearance isEqualToString:appeared]) {
        LOGE(@"Unexpected disk appeared data");
        return NO;
      }

      return YES;
    }]]);

  SNTProtobufEventLog *eventLog = [[SNTProtobufEventLog alloc] initWithLog:self.mockLogOutput];

  id eventLogMock = OCMPartialMock(eventLog);
  OCMExpect([eventLogMock serialForDevice:[OCMArg checkWithBlock:^BOOL(NSString *path) {
                            return [path isEqualToString:devicePath];
                          }]])
    .andReturn(serial);

  [eventLog logDiskAppeared:diskProperties];

  XCTAssertTrue(OCMVerifyAll(self.mockLogOutput) && OCMVerifyAll(eventLogMock),
                "Unable to verify all expectations");
  [eventLogMock stopMocking];
}

- (void)testLogDiskDisappeared {
  NSString *mount = @"/mnt/disappear";
  NSString *volume = @"Macintosh HD";
  NSString *bsdName = @"disk0s2";

  NSDictionary *diskProperties = @{
    @"DAVolumePath" : [NSURL URLWithString:mount],
    @"DAVolumeName" : volume,
    @"DAMediaBSDName" : bsdName,
  };

  OCMExpect([self.mockLogOutput logEvent:[OCMArg checkWithBlock:^BOOL(SNTSantaMessage *sm) {
                                  SNTLegacyDiskDisappeared *diskDisappeared = getEventForMessage(
                                    sm,
                                    SNTLegacyMessage_LegacyMessageType_OneOfCase_DiskDisappeared,
                                    @"diskDisappeared", [SNTLegacyDiskDisappeared class]);

                                  if (![diskDisappeared.mount isEqualToString:mount] ||
                                      ![diskDisappeared.volume isEqualToString:volume] ||
                                      ![diskDisappeared.bsdName isEqualToString:bsdName]) {
                                    LOGE(@"Unexpected disk disappeared data");
                                    return NO;
                                  }

                                  return YES;
                                }]]);

  SNTProtobufEventLog *eventLog = [[SNTProtobufEventLog alloc] initWithLog:self.mockLogOutput];
  [eventLog logDiskDisappeared:diskProperties];

  XCTAssertTrue(OCMVerifyAll(self.mockLogOutput), "Unable to verify all expectations");
}

- (void)testLogBundleHashingEvents {
  NSArray<SNTStoredEvent *> *storedEvents = @[
    createTestBundleStoredEvent(getBundleForSystemApplication(@"Calculator.app"), @"abc123",
                                @"xyz456"),
    createTestBundleStoredEvent(getBundleForSystemApplication(@"Calendar.app"), @"123abc",
                                @"456xyz"),
  ];

  for (SNTStoredEvent *storedEvent in storedEvents) {
    OCMExpect([self.mockLogOutput
      logEvent:[OCMArg checkWithBlock:^BOOL(SNTSantaMessage *sm) {
        SNTLegacyBundle *bundleEvent =
          getEventForMessage(sm, SNTLegacyMessage_LegacyMessageType_OneOfCase_Bundle, @"bundle",
                             [SNTLegacyBundle class]);

        if (![bundleEvent.sha256 isEqualToString:storedEvent.fileSHA256] ||
            ![bundleEvent.bundleHash isEqualToString:storedEvent.fileBundleHash] ||
            ![bundleEvent.bundleName isEqualToString:storedEvent.fileBundleName] ||
            ![bundleEvent.bundleId isEqualToString:storedEvent.fileBundleID] ||
            ![bundleEvent.bundlePath isEqualToString:storedEvent.fileBundlePath] ||
            ![bundleEvent.path isEqualToString:storedEvent.filePath]) {
          LOGE(@"Unexpected bundle event data for: %@", storedEvent.filePath);
          return NO;
        }

        return YES;
      }]]);
  }

  SNTProtobufEventLog *eventLog = [[SNTProtobufEventLog alloc] initWithLog:self.mockLogOutput];
  [eventLog logBundleHashingEvents:storedEvents];

  XCTAssertTrue(OCMVerifyAll(self.mockLogOutput), "Unable to verify all expectations");
}

- (void)testLogFork {
  santa_message_t santaMsg = getBasicSantaMessage(ACTION_NOTIFY_FORK);

  OCMExpect([self.mockLogOutput
    logEvent:[OCMArg checkWithBlock:^BOOL(SNTSantaMessage *sm) {
      SNTLegacyFork *forkEvent = getEventForMessage(
        sm, SNTLegacyMessage_LegacyMessageType_OneOfCase_Fork, @"fork", [SNTLegacyFork class]);

      if (!forkEvent.hasProcessInfo || forkEvent.processInfo == nil) {
        LOGE(@"Unexpected fork data");
        return NO;
      }

      assertProcessInfoMatchesExpected(forkEvent.processInfo, &santaMsg);

      return YES;
    }]]);

  SNTProtobufEventLog *eventLog = [[SNTProtobufEventLog alloc] initWithLog:self.mockLogOutput];
  [eventLog logFork:santaMsg];

  XCTAssertTrue(OCMVerifyAll(self.mockLogOutput), "Unable to verify all expectations");
}

- (void)testLogExit {
  santa_message_t santaMsg = getBasicSantaMessage(ACTION_NOTIFY_EXIT);

  OCMExpect([self.mockLogOutput
    logEvent:[OCMArg checkWithBlock:^BOOL(SNTSantaMessage *sm) {
      SNTLegacyExit *exitEvent = getEventForMessage(
        sm, SNTLegacyMessage_LegacyMessageType_OneOfCase_Exit, @"exit", [SNTLegacyExit class]);

      if (!exitEvent.hasProcessInfo || exitEvent.processInfo == nil) {
        LOGE(@"Unexpected exit data");
        return NO;
      }

      assertProcessInfoMatchesExpected(exitEvent.processInfo, &santaMsg);

      return YES;
    }]]);

  SNTProtobufEventLog *eventLog = [[SNTProtobufEventLog alloc] initWithLog:self.mockLogOutput];
  [eventLog logExit:santaMsg];

  XCTAssertTrue(OCMVerifyAll(self.mockLogOutput), "Unable to verify all expectations");
}

- (void)testLogAllowlist {
  SNTAllowlistInfo *allowlistInfo = [[SNTAllowlistInfo alloc] initWithPid:123
                                                               pidversion:456
                                                               targetPath:@"/sbin/launchd"
                                                                   sha256:@"abc123"];

  OCMExpect([self.mockLogOutput
    logEvent:[OCMArg checkWithBlock:^BOOL(SNTSantaMessage *sm) {
      SNTLegacyAllowlist *allowlistEvent =
        getEventForMessage(sm, SNTLegacyMessage_LegacyMessageType_OneOfCase_Allowlist, @"allowlist",
                           [SNTLegacyAllowlist class]);

      if (allowlistEvent.pid != allowlistInfo.pid ||
          allowlistEvent.pidversion != allowlistInfo.pidversion ||
          ![allowlistEvent.path isEqualToString:allowlistInfo.targetPath] ||
          ![allowlistEvent.sha256 isEqualToString:allowlistInfo.sha256]) {
        LOGE(@"Unexpected allowlist data");
        return NO;
      }

      return YES;
    }]]);

  SNTProtobufEventLog *eventLog = [[SNTProtobufEventLog alloc] initWithLog:self.mockLogOutput];
  [eventLog logAllowlist:allowlistInfo];

  XCTAssertTrue(OCMVerifyAll(self.mockLogOutput), "Unable to verify all expectations");
}

@end

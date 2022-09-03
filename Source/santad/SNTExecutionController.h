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

#import <Foundation/Foundation.h>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

#import "Source/common/SNTCommon.h"
#import "Source/common/SNTCommonEnums.h"

const static NSString *kBlockBinary = @"BlockBinary";
const static NSString *kAllowBinary = @"AllowBinary";
const static NSString *kBlockCertificate = @"BlockCertificate";
const static NSString *kAllowCertificate = @"AllowCertificate";
const static NSString *kBlockTeamID = @"BlockTeamID";
const static NSString *kAllowTeamID = @"AllowTeamID";
const static NSString *kBlockScope = @"BlockScope";
const static NSString *kAllowScope = @"AllowScope";
const static NSString *kAllowUnknown = @"AllowUnknown";
const static NSString *kBlockUnknown = @"BlockUnknown";
const static NSString *kAllowCompiler = @"AllowCompiler";
const static NSString *kAllowTransitive = @"AllowTransitive";
const static NSString *kUnknownEventState = @"Unknown";
const static NSString *kBlockPrinterWorkaround = @"BlockPrinterWorkaround";
const static NSString *kAllowNoFileInfo = @"AllowNoFileInfo";
const static NSString *kDenyNoFileInfo = @"DenyNoFileInfo";
const static NSString *kBlockLongPath = @"BlockLongPath";

@class SNTEventTable;
@class SNTNotificationQueue;
@class SNTRuleTable;
@class SNTSyncdQueue;

///
///  SNTExecutionController is responsible for handling binary execution requests:
///    + Uses SNTPolicyProcessor to make a decision about whether to allow or deny the binary.
///    + Sending the decision to the kernel as soon as possible
///    + (If denied or unknown) Storing details about the execution event to the database
///      for upload and spwaning santactl to quickly try and send that to the server.
///    + (If denied) Potentially sending a message to SantaGUI to notify the user
///
@interface SNTExecutionController : NSObject

- (instancetype)initWithRuleTable:(SNTRuleTable *)ruleTable
                       eventTable:(SNTEventTable *)eventTable
                    notifierQueue:(SNTNotificationQueue *)notifierQueue
                       syncdQueue:(SNTSyncdQueue *)syncdQueue;

///
///  Handles the logic of deciding whether to allow the binary to run or not, sends the response to
///  the given `postAction` block. Also logs the event to the log and if necessary stores the event
///  in the database and sends a notification to the GUI agent.
///
///  @param message The message received from the EndpointSecurity event provider.
///  @param postAction The block invoked with the desired response result.
///
- (void)validateExecEvent:(const santa::santad::event_providers::endpoint_security::Message &)esMsg
               postAction:(bool (^)(santa_action_t))postAction;

///
/// Perform light, synchronous processing of the given event to decide whether or not the
/// event should undergo full processing. The checks done by this function MUST NOT block
/// the thread (e.g. perform no XPC) and should be fast and efficient so as to mitigate
/// potential buildup of event backlog.
///
///  @param message The message received from the EndpointSecurity event provider.
///  @return bool True if the event should be processed, otherwise false.
///
- (bool)synchronousShouldProcessExecEvent:
  (const santa::santad::event_providers::endpoint_security::Message &)esMsg;

@end

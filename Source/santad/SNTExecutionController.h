/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTKernelCommon.h"
#include "Source/santad/EventProviders/SNTEventProvider.h"

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
const static NSString *kAllowNullVNode = @"AllowNullVNode";

@class MOLCodesignChecker;
@class SNTDriverManager;
@class SNTEventLog;
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

- (instancetype)initWithEventProvider:(id<SNTEventProvider>)eventProvider
                            ruleTable:(SNTRuleTable *)ruleTable
                           eventTable:(SNTEventTable *)eventTable
                        notifierQueue:(SNTNotificationQueue *)notifierQueue
                           syncdQueue:(SNTSyncdQueue *)syncdQueue;

///
///  Handles the logic of deciding whether to allow the binary to run or not, sends the response to
///  the kernel, logs the event to the log and if necessary stores the event in the database and
///  sends a notification to the GUI agent.
///
///  @param message The message sent from the kernel.
///
- (void)validateBinaryWithMessage:(santa_message_t)message;

@end

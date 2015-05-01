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

#include "SNTCommonEnums.h"

@class SNTCodesignChecker;
@class SNTDriverManager;
@class SNTEventTable;
@class SNTRuleTable;
@class SNTXPCConnection;

///
///  SNTExecutionController is responsible for everything that happens when a request to execute
///  a binary occurs:
///    + Making a decision about whether to allow or deny this binary based on any existing rules
///      for that specific binary, its signing certificate and the operating mode of santad.
///    + Sending the decision to the kernel as soon as possible
///    + (If denied or unknown) Storing details about the execution event to the database
///      for upload and spwaning santactl to quickly try and send that to the server.
///    + (If denied) Potentially sending a message to SantaGUI to notify the user
///    + Logging the event to the log file
///
@interface SNTExecutionController : NSObject

@property SNTDriverManager *driverManager;
@property SNTRuleTable *ruleTable;
@property SNTEventTable *eventTable;
@property SNTXPCConnection *notifierConnection;

- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager
                            ruleTable:(SNTRuleTable *)ruleTable
                           eventTable:(SNTEventTable *)eventTable
                   notifierConnection:(SNTXPCConnection *)notifierConn;

///
///  Handles the logic of deciding whether to allow the binary to run or not, sends the response to
///  the kernel, logs the event to the log and if necessary stores the event in the database and
///  sends a notification to the GUI agent.
///
///  @param path the binary that's being executed
///  @param userName the user who's executing the binary
///  @param pid the process id being executed
///  @param ppid the parent process id
///  @param vnodeId the id of the vnode being executed
///
- (void)validateBinaryWithPath:(NSString *)path
                      userName:(NSString *)userName
                           pid:(NSNumber *)pid
                          ppid:(NSNumber *)ppid
                       vnodeId:(uint64_t)vnodeId;

@end

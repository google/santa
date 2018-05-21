/// Copyright 2017 Google Inc. All rights reserved.
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

@class MOLXPCConnection;

@protocol SNTCommandProtocol

///
///  @return YES if command requires root.
///
+ (BOOL)requiresRoot;

///
///  @return YES if command requires connection to santad.
///
+ (BOOL)requiresDaemonConn;

///
///  A small summary of the command, to be printed with the list of available commands
///
+ (NSString *)shortHelpText;

///
///  A longer description of the command when the user runs <tt>santactl help x</tt>
///
+ (NSString *)longHelpText;

@end

@protocol SNTCommandRunProtocol

///
///  Called when the user is running the command
///  @param arguments an array of arguments passed in
///  @param daemonConn connection to santad. Will be nil if connection failed or
///      if @c requiresDaemonConn is @c NO
///
///  @note This method (or one of the methods it calls) is responsible for calling exit().
///
+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(MOLXPCConnection *)daemonConn;

@end

@interface SNTCommand : NSObject<SNTCommandRunProtocol>

@property(nonatomic,readonly) MOLXPCConnection *daemonConn;

///  Designated initializer
- (instancetype)initWithDaemonConnection:(MOLXPCConnection *)daemonConn;

- (void)runWithArguments:(NSArray *)arguments;

- (void)printErrorUsageAndExit:(NSString *)error;
@end


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

@import Foundation;

@class SNTXPCConnection;

///
///  Protocol that each command must adhere to.
///
@protocol SNTCommand<NSObject>

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

///
///  Called when the user is running the command
///  @param arguments an array of arguments passed in
///  @param daemonConn connection to santad. Will be nil if connection failed or
///      if @c requiresDaemonConn is @c NO
///
///  @note This method (or one of the methods it calls) is responsible for calling exit().
///
+ (void)runWithArguments:(NSArray *)arguments daemonConnection:(SNTXPCConnection *)daemonConn;
@end

///
///  Responsible for maintaining the list of available commands by name, printing their help text
///  when requested and launching them when requested. All of the methods in this class are
///  class methods because the @c registerCommand:named: method is called by the @c +load method
///  of each command class and so we cannot rely on its instantiation.
///
@interface SNTCommandController : NSObject

///
///  Register a new command with the specified name. Do not use this directly, use the
///  @c REGISTER_COMMAND_NAME macro instead.
///
+ (void)registerCommand:(Class<SNTCommand>)command named:(NSString *)name;

///
///  @return a usage string listing all of the available commands
///
+ (NSString *)usage;

///
///  @return the descriptive text for the given command, if it exists
///
+ (NSString *)helpForCommandWithName:(NSString *)command;

///
///  @return YES if @c commandName exists.
///
+ (BOOL)hasCommandWithName:(NSString *)commandName;

///
///  Runs the given command with the given arguments.
///
///  @param commandName the name of a previously-registered command
///  @param arguments an array of arguments to pass to the command
///
+ (void)runCommandWithName:(NSString *)commandName arguments:(NSArray *)arguments;

@end

///
///  This macro registers a given class as a command with the name passed in @c a (which must be an
///  NSString). Must be placed just inside the implementation of the class, ideally at the top.
///  The class that uses this macro must implement the @c SNTCommand protcol.
///
#define REGISTER_COMMAND_NAME(a) \
    + (void)load { [SNTCommandController registerCommand:[self class] named:a]; }

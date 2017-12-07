//
//  SNTCompilerController.h
//  Santa
//
//  Created by Phillip Nguyen on 10/18/17.
//
//

#import <Foundation/Foundation.h>
#import "SNTKernelCommon.h"

@class SNTDriverManager;

@interface SNTCompilerController : NSObject

// Designated initializer for SNTCompilerController.  It must be passed a SNTDriverManager so that
// it can communicate with the kernel (sending it a processTerminated message).
- (instancetype)initWithDriverManager:(SNTDriverManager *)driverManager;

// Whenever a compiler binary is executed, this starts monitoring its pid so that we can send a
// message back to the kernel when the process terminates, notifying the kernel that it should
// remove the pid from its cache of pids associated with compiler processes.
- (void)monitorCompilerProcess:(pid_t)pid;

// Whenever an executable file is closed or renamed whitelist the resulting file.
// We assume that we have already determined that the writing process was a compiler.
- (void)checkForNewExecutable:(santa_message_t)message;
@end

//
//  SNTCompilerController.h
//  Santa
//
//  Created by Phillip Nguyen on 10/18/17.
//
//

#import <Foundation/Foundation.h>
#import "SNTKernelCommon.h"

@interface SNTCompilerController : NSObject
// Store vnode id associated with a compiler the first time it is executed.
- (void)cacheCompilerWithVnodeId:(uint64_t)vnodeId;

// Remove a vnode id from cache if it is not associated with a compiler.
- (void)forgetVnodeId:(uint64_t)vnodeId;

// Whenever a binary is executed, check the vnode id cache to determine if it is a compiler,
// and if it is a compiler then cache its PID for later use.
- (void)cacheExecution:(santa_message_t)message;


// Whenever an executable file is closed or renamed, check the cache of compiler PIDs to see if
// the writing process is a compiler and, if so, whitelist the resulting file.
- (void)checkForCompiler:(santa_message_t)message;
@end

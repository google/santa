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
{
  int _kq;
}


- (void)cacheCompilerWithVnodeId:(uint64_t)vnodeId;
- (void)forgetVnodeId:(uint64_t)vnodeId;
- (void)cacheExecution:(santa_message_t)message;
- (void)checkForCompiler:(santa_message_t)message;
@end

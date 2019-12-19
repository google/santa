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

#import <Cocoa/Cocoa.h>
#import <SystemExtensions/SystemExtensions.h>

#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santa/SNTAppDelegate.h"

@interface SNTSystemExtensionDelegate : NSObject<OSSystemExtensionRequestDelegate>
@end

@implementation SNTSystemExtensionDelegate

#pragma mark OSSystemExtensionRequestDelegate

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request
                  actionForReplacingExtension:(OSSystemExtensionProperties *)old
                                withExtension:(OSSystemExtensionProperties *)new
    API_AVAILABLE(macos(10.15)) {
  NSLog(@"SystemExtension \"%@\" request for replacement", request.identifier);
  return OSSystemExtensionReplacementActionReplace;
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request API_AVAILABLE(macos(10.15)) {
  NSLog(@"SystemExtension \"%@\" request needs user approval", request.identifier);
}

- (void)request:(OSSystemExtensionRequest *)request
    didFailWithError:(NSError *)error API_AVAILABLE(macos(10.15)) {
  NSLog(@"SystemExtension \"%@\" request did fail: %@", request.identifier, error);
  exit((int)error.code);
}

- (void)request:(OSSystemExtensionRequest *)request
    didFinishWithResult:(OSSystemExtensionRequestResult)result API_AVAILABLE(macos(10.15)) {
  NSLog(@"SystemExtension \"%@\" request did finish: %ld", request.identifier, (long)result);
  exit(0);
}

@end

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    NSNumber *sysxOperation;
    NSArray *args = [NSProcessInfo processInfo].arguments;
    if ([args containsObject:@"--load-system-extension"]) {
      sysxOperation = @(1);
    } else if ([args containsObject:@"--unload-system-extension"]) {
      sysxOperation = @(2);
    }
    if (sysxOperation) {
      if (@available(macOS 10.15, *)) {
        NSString *e = [SNTXPCControlInterface systemExtensionID];
        dispatch_queue_t q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0);
        OSSystemExtensionRequest *req;
        if (sysxOperation.intValue == 1) {
          NSLog(@"Requesting SystemExtension activation");
          req = [OSSystemExtensionRequest activationRequestForExtension:e queue:q];
        } else if (sysxOperation.intValue == 2) {
          NSLog(@"Requesting SystemExtension deactivation");
          req = [OSSystemExtensionRequest deactivationRequestForExtension:e queue:q];
        }
        if (req) {
          SNTSystemExtensionDelegate *ed = [[SNTSystemExtensionDelegate alloc] init];
          req.delegate = ed;
          [[OSSystemExtensionManager sharedManager] submitRequest:req];
          dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 60), q, ^{
            exit(1);
          });
          [[NSRunLoop mainRunLoop] run];
        }
      } else {
        exit(1);
      }
    }

    NSApplication *app = [NSApplication sharedApplication];
    SNTAppDelegate *delegate = [[SNTAppDelegate alloc] init];
    [app setDelegate:delegate];
    [app finishLaunching];
    [app run];
  }
}

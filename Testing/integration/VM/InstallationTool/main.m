// Adapted from
// https://developer.apple.com/documentation/virtualization/running_macos_in_a_virtual_machine_on_apple_silicon_macs
/*
Copyright © 2022 Apple Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#import "MacOSRestoreImage.h"
#import "MacOSVirtualMachineInstaller.h"
#import "Testing/integration/VM/Common/Error.h"

#import <Foundation/Foundation.h>

int main(int argc, const char *argv[]) {
#ifdef __arm64__
  @autoreleasepool {
    MacOSVirtualMachineInstaller *installer = [MacOSVirtualMachineInstaller new];

    if (argc == 3) {
      NSString *bundleDir = @(argv[1]);
      if (![bundleDir hasSuffix:@"/"]) {
        bundleDir = [bundleDir stringByAppendingString:@"/"];
      }
      NSString *ipswPath = @(argv[2]);

      NSURL *ipswURL = [[NSURL alloc] initFileURLWithPath:ipswPath];
      if (!ipswURL.isFileURL) {
        abortWithErrorMessage(@"The provided IPSW path is not a valid file URL.");
      }

      [installer setUpVirtualMachineArtifacts:bundleDir];
      [installer installMacOS:bundleDir ipswURL:ipswURL];

      dispatch_main();
    } else if (argc == 2) {
      NSString *bundleDir = @(argv[1]);
      if (![bundleDir hasSuffix:@"/"]) {
        bundleDir = [bundleDir stringByAppendingString:@"/"];
      }
      [installer setUpVirtualMachineArtifacts:bundleDir];

      MacOSRestoreImage *restoreImage = [MacOSRestoreImage new];
      [restoreImage downloadToBundle:bundleDir
               withCompletionHandler:^(NSURL *ipswURL) {
                 // Install from the restore image that has been downloaded.
                 [installer installMacOS:bundleDir ipswURL:ipswURL];
               }];

      dispatch_main();
    } else {
      NSLog(@"Usage: InstallationTool BUNDLE_DIR [IPSW_URL]");
      exit(-1);
    }
  }
#else
  NSLog(@"This tool can only be run on Apple Silicon Macs.");
  exit(-1);
#endif
}

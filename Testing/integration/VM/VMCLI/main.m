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
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

#import "Testing/integration/VM/Common/Error.h"
#import "Testing/integration/VM/Common/MacOSVirtualMachineConfigurationHelper.h"

@interface MacOSVirtualMachineDelegate : NSObject <VZVirtualMachineDelegate>
@end

@implementation MacOSVirtualMachineDelegate
- (void)virtualMachine:(VZVirtualMachine *)virtualMachine didStopWithError:(NSError *)error {
  abortWithErrorMessage(error.localizedDescription);
}

- (void)guestDidStopVirtualMachine:(VZVirtualMachine *)virtualMachine {
  NSLog(@"Guest did stop virtual machine.");
  exit(0);
}
@end

int main(int argc, const char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s bundle_path runner_disk [usb_disk]", argv[0]);
    exit(-1);
  }

  NSString *bundleDir = @(argv[1]);
  if (![bundleDir hasSuffix:@"/"]) {
    bundleDir = [bundleDir stringByAppendingString:@"/"];
  }

  NSString *runnerDisk = @(argv[2]);

  NSString *usbDisk = NULL;
  if (argc > 3) {
    usbDisk = @(argv[3]);
  }

  VZVirtualMachine *vm =
    [MacOSVirtualMachineConfigurationHelper createVirtualMachineWithBundleDir:bundleDir
                                                                       roDisk:runnerDisk
                                                                      usbDisk:usbDisk];

  MacOSVirtualMachineDelegate *delegate = [MacOSVirtualMachineDelegate new];
  vm.delegate = delegate;

  [vm startWithCompletionHandler:^(NSError *_Nullable error) {
    if (error) {
      NSLog(@"%@", error.localizedDescription);
      abort();
    }
  }];

  dispatch_main();
}

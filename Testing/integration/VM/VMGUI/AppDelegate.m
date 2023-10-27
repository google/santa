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

#import "AppDelegate.h"

#import "Testing/integration/VM/Common/Error.h"
#import "Testing/integration/VM/Common/MacOSVirtualMachineConfigurationHelper.h"
#import "Testing/integration/VM/Common/MacOSVirtualMachineDelegate.h"

#import <Virtualization/Virtualization.h>

// MARK: AppDelegate

@interface AppDelegate ()

@property(weak) IBOutlet VZVirtualMachineView *virtualMachineView;

@property(strong) IBOutlet NSWindow *window;

@end

@implementation AppDelegate {
  VZVirtualMachine *_virtualMachine;
  MacOSVirtualMachineDelegate *_delegate;
}

// MARK: Start the Virtual Machine

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
#ifdef __arm64__
  dispatch_async(dispatch_get_main_queue(), ^{
    NSMutableArray *args = [NSMutableArray arrayWithArray:[[NSProcessInfo processInfo] arguments]];

    VZMacOSVirtualMachineStartOptions *options = [VZMacOSVirtualMachineStartOptions new];
    NSString *bundleDir;
    NSString *roDisk;
    NSString *usbDisk;

    [args removeObjectAtIndex:0];

    if (args.count == 0) {
      abortWithErrorMessage(@"Usage: VMGUI [-recovery] bundle_path [ro_disk] [usb_disk]");
    }

    if ([args[0] isEqualToString:@"-recovery"]) {
      options.startUpFromMacOSRecovery = YES;
      [args removeObjectAtIndex:0];
      if (args.count == 0) {
        abortWithErrorMessage(@"Usage: VMGUI [-recovery] bundle_path [ro_disk] [usb_disk]");
      }
    }

    bundleDir = args[0];
    [args removeObjectAtIndex:0];
    if (args.count) {
      roDisk = args[0];
      [args removeObjectAtIndex:0];
    }

    if (args.count) {
      usbDisk = args[0];
      [args removeObjectAtIndex:0];
    }

    if (![bundleDir hasSuffix:@"/"]) {
      bundleDir = [bundleDir stringByAppendingString:@"/"];
    }

    VZVirtualMachine *vm =
      [MacOSVirtualMachineConfigurationHelper createVirtualMachineWithBundleDir:bundleDir
                                                                         roDisk:roDisk
                                                                        usbDisk:usbDisk];
    self->_virtualMachine = vm;

    self->_delegate = [MacOSVirtualMachineDelegate new];
    self->_virtualMachine.delegate = self->_delegate;
    self->_virtualMachineView.virtualMachine = self->_virtualMachine;

    [self->_virtualMachine startWithOptions:options
                          completionHandler:^(NSError *_Nullable error) {
                            if (error) {
                              abortWithErrorMessage(error.localizedDescription);
                            }
                          }];
  });
#endif
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
  return YES;
}

@end

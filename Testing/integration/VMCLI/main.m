#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

#import "MacOSVirtualMachineConfigurationHelper.h"

@interface MacOSVirtualMachineDelegate : NSObject<VZVirtualMachineDelegate>
@end

@implementation MacOSVirtualMachineDelegate
- (void)virtualMachine:(VZVirtualMachine *)virtualMachine didStopWithError:(NSError *)error
{
    NSLog(@"Virtual Machine did stop with error. %@", error.localizedDescription);
    exit(-1);
}

- (void)guestDidStopVirtualMachine:(VZVirtualMachine *)virtualMachine
{
    NSLog(@"Guest did stop virtual machine.");
    exit(0);
}
@end


int main(int argc, const char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s bundle_path", argv[0]);
    exit(-1);
  }

  NSString *bundleDir = @(argv[1]);
  if (![bundleDir hasSuffix:@"/"]) {
    bundleDir = [bundleDir stringByAppendingString:@"/"];
  }

  VZVirtualMachine *vm = [MacOSVirtualMachineConfigurationHelper createVirtualMachineWithBundleDir:bundleDir];

  MacOSVirtualMachineDelegate *delegate = [MacOSVirtualMachineDelegate new];
  vm.delegate = delegate;

  [vm startWithCompletionHandler:^(NSError * _Nullable error) {
      if (error) {
          NSLog(@"%@", error.localizedDescription);
          abort();
      }
  }];

  dispatch_main();
}

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

#ifdef __arm64__

#import "MacOSVirtualMachineInstaller.h"

#import "Testing/integration/VM/Common/Error.h"
#import "Testing/integration/VM/Common/MacOSVirtualMachineConfigurationHelper.h"
#import "Testing/integration/VM/Common/MacOSVirtualMachineDelegate.h"

#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>
#import <sys/stat.h>

@implementation MacOSVirtualMachineInstaller {
  VZVirtualMachine *_virtualMachine;
  MacOSVirtualMachineDelegate *_delegate;
}

// MARK: - Internal helper methods.

static void createVMBundle(NSString *bundleDir) {
  int fd = mkdir([bundleDir UTF8String], S_IRWXU | S_IRWXG | S_IRWXO);
  if (fd == -1) {
    if (errno == EEXIST) {
      return;
    }
    abortWithErrorMessage(@"Failed to create VM.bundle.");
  }

  int result = close(fd);
  if (result) {
    abortWithErrorMessage(@"Failed to close VM.bundle.");
  }
}

// Create an empty disk image for the Virtual Machine
static void createDiskImage(NSURL *diskLocation, long diskSize) {
  int fd = open([diskLocation fileSystemRepresentation], O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    abortWithErrorMessage(@"Cannot create disk image.");
  }

  int result = ftruncate(fd, diskSize);
  if (result) {
    abortWithErrorMessage(@"ftruncate() failed.");
  }

  result = close(fd);
  if (result) {
    abortWithErrorMessage(@"Failed to close the disk image.");
  }
}

// MARK: Create the Mac Platform Configuration

- (VZMacPlatformConfiguration *)createMacPlatformConfiguration:
                                  (VZMacOSConfigurationRequirements *)macOSConfiguration
                                                 withBundleDir:(NSString *)bundleDir {
  VZMacPlatformConfiguration *macPlatformConfiguration = [[VZMacPlatformConfiguration alloc] init];

  NSError *error;
  NSURL *auxURL =
    [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"AuxiliaryStorage"]];
  VZMacAuxiliaryStorage *auxiliaryStorage = [[VZMacAuxiliaryStorage alloc]
    initCreatingStorageAtURL:auxURL
               hardwareModel:macOSConfiguration.hardwareModel
                     options:VZMacAuxiliaryStorageInitializationOptionAllowOverwrite
                       error:&error];
  if (!auxiliaryStorage) {
    abortWithErrorMessage([NSString
      stringWithFormat:@"Failed to create auxiliary storage. %@", error.localizedDescription]);
  }

  macPlatformConfiguration.hardwareModel = macOSConfiguration.hardwareModel;
  macPlatformConfiguration.auxiliaryStorage = auxiliaryStorage;
  macPlatformConfiguration.machineIdentifier = [[VZMacMachineIdentifier alloc] init];

  // Store the hardware model and machine identifier to disk so that we can retrieve them for
  // subsequent boots.
  NSURL *modelURL =
    [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"HardwareModel"]];
  [macPlatformConfiguration.hardwareModel.dataRepresentation writeToURL:modelURL atomically:YES];
  NSURL *machineIdURL =
    [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"MachineIdentifier"]];
  [macPlatformConfiguration.machineIdentifier.dataRepresentation writeToURL:machineIdURL
                                                                 atomically:YES];

  return macPlatformConfiguration;
}

// MARK: Create the Virtual Machine Configuration and instantiate the Virtual Machine

- (void)setupVirtualMachineWithMacOSConfigurationRequirements:
          (VZMacOSConfigurationRequirements *)macOSConfiguration
                                                withBundleDir:(NSString *)bundleDir {
  VZVirtualMachineConfiguration *configuration = [VZVirtualMachineConfiguration new];

  configuration.platform = [self createMacPlatformConfiguration:macOSConfiguration
                                                  withBundleDir:bundleDir];
  assert(configuration.platform);

  configuration.CPUCount = [MacOSVirtualMachineConfigurationHelper computeCPUCount];
  if (configuration.CPUCount < macOSConfiguration.minimumSupportedCPUCount) {
    abortWithErrorMessage(@"CPUCount is not supported by the macOS configuration.");
  }

  configuration.memorySize = [MacOSVirtualMachineConfigurationHelper computeMemorySize];
  if (configuration.memorySize < macOSConfiguration.minimumSupportedMemorySize) {
    abortWithErrorMessage(@"memorySize is not supported by the macOS configuration.");
  }

  // Create a 64 GB disk image.
  NSURL *diskURL =
    [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"Disk.img"]];
  createDiskImage(diskURL, 64ull * 1024ull * 1024ull * 1024ull);

  configuration.bootLoader = [MacOSVirtualMachineConfigurationHelper createBootLoader];
  configuration.graphicsDevices =
    @[ [MacOSVirtualMachineConfigurationHelper createGraphicsDeviceConfiguration] ];
  configuration.storageDevices =
    @[ [MacOSVirtualMachineConfigurationHelper createBlockDeviceConfigurationForDisk:diskURL
                                                                            readOnly:NO] ];
  configuration.networkDevices =
    @[ [MacOSVirtualMachineConfigurationHelper createNetworkDeviceConfiguration] ];
  configuration.pointingDevices =
    @[ [MacOSVirtualMachineConfigurationHelper createPointingDeviceConfiguration] ];
  configuration.keyboards =
    @[ [MacOSVirtualMachineConfigurationHelper createKeyboardConfiguration] ];
  configuration.audioDevices =
    @[ [MacOSVirtualMachineConfigurationHelper createAudioDeviceConfiguration] ];
  assert([configuration validateWithError:nil]);

  self->_virtualMachine = [[VZVirtualMachine alloc] initWithConfiguration:configuration];
  self->_delegate = [MacOSVirtualMachineDelegate new];
  self->_virtualMachine.delegate = self->_delegate;
}

- (void)startInstallationWithRestoreImageFileURL:(NSURL *)restoreImageFileURL {
  VZMacOSInstaller *installer =
    [[VZMacOSInstaller alloc] initWithVirtualMachine:self->_virtualMachine
                                     restoreImageURL:restoreImageFileURL];

  NSLog(@"Starting installation.");
  [installer installWithCompletionHandler:^(NSError *error) {
    if (error) {
      abortWithErrorMessage([NSString stringWithFormat:@"%@", error.localizedDescription]);
    } else {
      NSLog(@"Installation succeeded.");
    }
  }];

  [installer.progress addObserver:self
                       forKeyPath:@"fractionCompleted"
                          options:NSKeyValueObservingOptionInitial | NSKeyValueObservingOptionNew
                          context:nil];
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary *)change
                       context:(void *)context {
  if ([keyPath isEqualToString:@"fractionCompleted"] && [object isKindOfClass:[NSProgress class]]) {
    NSProgress *progress = (NSProgress *)object;
    NSLog(@"Installation progress: %f.", progress.fractionCompleted * 100);

    if (progress.finished) {
      [progress removeObserver:self forKeyPath:@"fractionCompleted"];
    }
  }
}

// MARK: - Public methods.

- (void)setUpVirtualMachineArtifacts:(NSString *)bundleDir {
  createVMBundle(bundleDir);
}

// MARK: Begin macOS installation

- (void)installMacOS:(NSString *)bundleDir ipswURL:(NSURL *)ipswURL {
  NSLog(@"Attempting to install from IPSW at %s\n", [ipswURL fileSystemRepresentation]);
  [VZMacOSRestoreImage loadFileURL:ipswURL
                 completionHandler:^(VZMacOSRestoreImage *restoreImage, NSError *error) {
                   if (error) {
                     abortWithErrorMessage(error.localizedDescription);
                   }

                   VZMacOSConfigurationRequirements *macOSConfiguration =
                     restoreImage.mostFeaturefulSupportedConfiguration;
                   if (!macOSConfiguration || !macOSConfiguration.hardwareModel.supported) {
                     abortWithErrorMessage(@"No supported Mac configuration.");
                   }

                   dispatch_async(dispatch_get_main_queue(), ^{
                     [self setupVirtualMachineWithMacOSConfigurationRequirements:macOSConfiguration
                                                                   withBundleDir:bundleDir];
                     [self startInstallationWithRestoreImageFileURL:ipswURL];
                   });
                 }];
}

@end

#endif

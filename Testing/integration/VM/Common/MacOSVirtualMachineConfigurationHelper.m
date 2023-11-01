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

#import "MacOSVirtualMachineConfigurationHelper.h"

#import <Foundation/Foundation.h>

@implementation MacOSVirtualMachineConfigurationHelper

+ (NSUInteger)computeCPUCount {
  NSUInteger totalAvailableCPUs = [[NSProcessInfo processInfo] processorCount];
  NSUInteger virtualCPUCount = totalAvailableCPUs <= 1 ? 1 : totalAvailableCPUs - 1;
  virtualCPUCount = MAX(virtualCPUCount, VZVirtualMachineConfiguration.minimumAllowedCPUCount);
  virtualCPUCount = MIN(virtualCPUCount, VZVirtualMachineConfiguration.maximumAllowedCPUCount);

  return virtualCPUCount;
}

+ (uint64_t)computeMemorySize {
  // We arbitrarily choose 4GB.
  uint64_t memorySize = 4ull * 1024ull * 1024ull * 1024ull;
  memorySize = MAX(memorySize, VZVirtualMachineConfiguration.minimumAllowedMemorySize);
  memorySize = MIN(memorySize, VZVirtualMachineConfiguration.maximumAllowedMemorySize);

  return memorySize;
}

+ (VZMacOSBootLoader *)createBootLoader {
  return [[VZMacOSBootLoader alloc] init];
}

+ (VZMacGraphicsDeviceConfiguration *)createGraphicsDeviceConfiguration {
  VZMacGraphicsDeviceConfiguration *graphicsConfiguration =
    [[VZMacGraphicsDeviceConfiguration alloc] init];
  graphicsConfiguration.displays = @[
    // We abitrarily choose the resolution of the display to be 1920 x 1200.
    [[VZMacGraphicsDisplayConfiguration alloc] initWithWidthInPixels:1920
                                                      heightInPixels:1200
                                                       pixelsPerInch:80],
  ];

  return graphicsConfiguration;
}

+ (VZVirtioBlockDeviceConfiguration *)createBlockDeviceConfigurationForDisk:(NSURL *)diskURL
                                                                   readOnly:(BOOL)ro {
  NSError *error;
  VZDiskImageStorageDeviceAttachment *diskAttachment =
    [[VZDiskImageStorageDeviceAttachment alloc] initWithURL:diskURL readOnly:ro error:&error];
  if (!diskAttachment) {
    NSLog(@"Failed to create VZDiskImageStorageDeviceAttachment: %@", error.localizedDescription);
    exit(-1);
  }
  VZVirtioBlockDeviceConfiguration *disk =
    [[VZVirtioBlockDeviceConfiguration alloc] initWithAttachment:diskAttachment];

  return disk;
}

+ (VZUSBMassStorageDeviceConfiguration *)createUSBDeviceConfigurationForDisk:(NSURL *)diskURL
                                                                   readOnly:(BOOL)ro {
  NSError *error;
  VZDiskImageStorageDeviceAttachment *diskAttachment =
    [[VZDiskImageStorageDeviceAttachment alloc] initWithURL:diskURL readOnly:ro error:&error];
  if (!diskAttachment) {
    NSLog(@"Failed to create VZDiskImageStorageDeviceAttachment: %@", error.localizedDescription);
    exit(-1);
  }
  VZUSBMassStorageDeviceConfiguration *disk =
    [[VZUSBMassStorageDeviceConfiguration alloc] initWithAttachment:diskAttachment];

  return disk;
}

+ (VZVirtioNetworkDeviceConfiguration *)createNetworkDeviceConfiguration {
  VZNATNetworkDeviceAttachment *natAttachment = [[VZNATNetworkDeviceAttachment alloc] init];
  VZVirtioNetworkDeviceConfiguration *networkConfiguration =
    [[VZVirtioNetworkDeviceConfiguration alloc] init];
  networkConfiguration.attachment = natAttachment;

  return networkConfiguration;
}

+ (VZUSBScreenCoordinatePointingDeviceConfiguration *)createPointingDeviceConfiguration {
  return [[VZUSBScreenCoordinatePointingDeviceConfiguration alloc] init];
}

+ (VZUSBKeyboardConfiguration *)createKeyboardConfiguration {
  return [[VZUSBKeyboardConfiguration alloc] init];
}

+ (VZVirtioSoundDeviceConfiguration *)createAudioDeviceConfiguration {
  VZVirtioSoundDeviceConfiguration *audioDeviceConfiguration =
    [[VZVirtioSoundDeviceConfiguration alloc] init];

  VZVirtioSoundDeviceInputStreamConfiguration *inputStream =
    [[VZVirtioSoundDeviceInputStreamConfiguration alloc] init];
  inputStream.source = [[VZHostAudioInputStreamSource alloc] init];

  VZVirtioSoundDeviceOutputStreamConfiguration *outputStream =
    [[VZVirtioSoundDeviceOutputStreamConfiguration alloc] init];
  outputStream.sink = [[VZHostAudioOutputStreamSink alloc] init];

  audioDeviceConfiguration.streams = @[ inputStream, outputStream ];

  return audioDeviceConfiguration;
}

+ (VZMacPlatformConfiguration *)createMacPlatformConfigurationWithBundleDir:(NSString *)bundleDir {
  if (![bundleDir hasSuffix:@"/"]) {
    bundleDir = [bundleDir stringByAppendingString:@"/"];
  }

  if (![[NSFileManager defaultManager] fileExistsAtPath:bundleDir]) {
    NSLog(@"Missing virtual machine bundle at %@. Run InstallationTool first to create it.",
          bundleDir);
    exit(-1);
  }

  VZMacPlatformConfiguration *macPlatformConfiguration = [[VZMacPlatformConfiguration alloc] init];
  NSURL *auxURL =
    [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"AuxiliaryStorage"]];
  VZMacAuxiliaryStorage *auxiliaryStorage =
    [[VZMacAuxiliaryStorage alloc] initWithContentsOfURL:auxURL];
  macPlatformConfiguration.auxiliaryStorage = auxiliaryStorage;

  NSURL *modelURL =
    [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"HardwareModel"]];
  NSData *hardwareModelData = [[NSData alloc] initWithContentsOfURL:modelURL];
  if (!hardwareModelData) {
    NSLog(@"Failed to read hardware model data");
    exit(-1);
  }

  VZMacHardwareModel *hardwareModel =
    [[VZMacHardwareModel alloc] initWithDataRepresentation:hardwareModelData];
  if (!hardwareModel) {
    NSLog(@"Failed to create hardware model");
    exit(-1);
  }

  if (!hardwareModel.supported) {
    NSLog(@"Hardware model not supported on current host");
    exit(-1);
  }
  macPlatformConfiguration.hardwareModel = hardwareModel;

  NSURL *idURL =
    [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"MachineIdentifier"]];
  NSData *machineIdentifierData = [[NSData alloc] initWithContentsOfURL:idURL];
  if (!machineIdentifierData) {
    NSLog(@"Failed to read machine identifier data");
    exit(-1);
  }

  VZMacMachineIdentifier *machineIdentifier =
    [[VZMacMachineIdentifier alloc] initWithDataRepresentation:machineIdentifierData];
  if (!machineIdentifier) {
    NSLog(@"Failed to create machine identifier");
    exit(-1);
  }
  macPlatformConfiguration.machineIdentifier = machineIdentifier;

  return macPlatformConfiguration;
}

+ (VZVirtualMachineConfiguration *)createBaseVirtualMachineConfigurationWithBundleDir:
  (NSString *)bundleDir {
  VZVirtualMachineConfiguration *configuration = [VZVirtualMachineConfiguration new];

  configuration.platform = [self createMacPlatformConfigurationWithBundleDir:bundleDir];
  configuration.CPUCount = [self computeCPUCount];
  configuration.memorySize = [self computeMemorySize];
  configuration.bootLoader = [self createBootLoader];
  configuration.graphicsDevices = @[ [self createGraphicsDeviceConfiguration] ];
  NSURL *diskURL =
    [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"Disk.img"]];
  configuration.storageDevices = @[ [self createBlockDeviceConfigurationForDisk:diskURL
                                                                       readOnly:NO] ];
  configuration.networkDevices = @[ [self createNetworkDeviceConfiguration] ];
  configuration.pointingDevices = @[ [self createPointingDeviceConfiguration] ];
  configuration.keyboards = @[ [self createKeyboardConfiguration] ];
  configuration.audioDevices = @[ [self createAudioDeviceConfiguration] ];

  return configuration;
}

+ (VZVirtualMachine *)createVirtualMachineWithBundleDir:(NSString *)bundleDir
                                                 roDisk:(NSString *)roDisk
                                                usbDisk:(NSString*)usbDisk {
  VZVirtualMachineConfiguration *configuration =
    [self createBaseVirtualMachineConfigurationWithBundleDir:bundleDir];
  if (roDisk && ![roDisk isEqualToString:@""]) {
    configuration.storageDevices = [configuration.storageDevices
      arrayByAddingObject:[self createBlockDeviceConfigurationForDisk:[[NSURL alloc]
                                                                        initFileURLWithPath:roDisk]
                                                             readOnly:YES]];
  }
  if (usbDisk && ![usbDisk isEqualToString:@""]) {
    configuration.storageDevices = [configuration.storageDevices
      arrayByAddingObject:[self createUSBDeviceConfigurationForDisk:[[NSURL alloc]
                                                                        initFileURLWithPath:usbDisk]
                                                             readOnly:NO]];
  }
  NSError *error;
  if (![configuration validateWithError:&error]) {
    NSLog(@"Failed to validate configuration: %@", error.localizedDescription);
    exit(-1);
  }

  return [[VZVirtualMachine alloc] initWithConfiguration:configuration];
}

+ (VZVirtualMachine *)createVirtualMachineWithBundleDir:(NSString *)bundleDir {
  return [self createVirtualMachineWithBundleDir:bundleDir roDisk:nil usbDisk:nil];
}

@end

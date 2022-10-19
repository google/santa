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

#ifndef MacOSVirtualMachineConfigurationHelper_h
#define MacOSVirtualMachineConfigurationHelper_h

#import <Virtualization/Virtualization.h>

@interface MacOSVirtualMachineConfigurationHelper : NSObject

+ (instancetype)new NS_UNAVAILABLE;
- (instancetype)init NS_UNAVAILABLE;

+ (NSUInteger)computeCPUCount;
+ (uint64_t)computeMemorySize;
+ (VZMacOSBootLoader *)createBootLoader;
+ (VZMacGraphicsDeviceConfiguration *)createGraphicsDeviceConfiguration;
+ (VZVirtioBlockDeviceConfiguration *)createBlockDeviceConfigurationForDisk:(NSURL *)disk
                                                                   readOnly:(BOOL)ro;
+ (VZVirtioNetworkDeviceConfiguration *)createNetworkDeviceConfiguration;
+ (VZUSBScreenCoordinatePointingDeviceConfiguration *)createPointingDeviceConfiguration;
+ (VZUSBKeyboardConfiguration *)createKeyboardConfiguration;
+ (VZVirtioSoundDeviceConfiguration *)createAudioDeviceConfiguration;
+ (VZMacPlatformConfiguration *)createMacPlatformConfigurationWithBundleDir:(NSString *)bundleDir;
+ (VZVirtualMachineConfiguration *)createBaseVirtualMachineConfigurationWithBundleDir:
  (NSString *)bundleDir;
+ (VZVirtualMachine *)createVirtualMachineWithBundleDir:(NSString *)bundleDir;
+ (VZVirtualMachine *)createVirtualMachineWithBundleDir:(NSString *)bundleDir
                                                 roDisk:(NSString *)roDisk;

@end

#endif

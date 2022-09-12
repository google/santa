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
+ (VZVirtioBlockDeviceConfiguration *)createBlockDeviceConfigurationForDisk:(NSURL *)disk readOnly:(BOOL)ro;
+ (VZVirtioNetworkDeviceConfiguration *)createNetworkDeviceConfiguration;
+ (VZUSBScreenCoordinatePointingDeviceConfiguration *)createPointingDeviceConfiguration;
+ (VZUSBKeyboardConfiguration *)createKeyboardConfiguration;
+ (VZVirtioSoundDeviceConfiguration *)createAudioDeviceConfiguration;
+ (VZMacPlatformConfiguration *)createMacPlatformConfigurationWithBundleDir:(NSString *)bundleDir;
+ (VZVirtualMachineConfiguration *)createBaseVirtualMachineConfigurationWithBundleDir:(NSString *)bundleDir;
+ (VZVirtualMachine *)createVirtualMachineWithBundleDir:(NSString *)bundleDir;
+ (VZVirtualMachine *)createVirtualMachineWithBundleDir:(NSString *)bundleDir roDisk:(NSString *)roDisk;

@end

#endif

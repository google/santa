#import "MacOSVirtualMachineConfigurationHelper.h"

#import <Foundation/Foundation.h>
#include <err.h>

@implementation MacOSVirtualMachineConfigurationHelper

+ (NSUInteger)computeCPUCount
{
    NSUInteger totalAvailableCPUs = [[NSProcessInfo processInfo] processorCount];
    NSUInteger virtualCPUCount = totalAvailableCPUs <= 1 ? 1 : totalAvailableCPUs - 1;
    virtualCPUCount = MAX(virtualCPUCount, VZVirtualMachineConfiguration.minimumAllowedCPUCount);
    virtualCPUCount = MIN(virtualCPUCount, VZVirtualMachineConfiguration.maximumAllowedCPUCount);

    return virtualCPUCount;
}

+ (uint64_t)computeMemorySize
{
    // We arbitrarily choose 4GB.
    uint64_t memorySize = 4ull * 1024ull * 1024ull * 1024ull;
    memorySize = MAX(memorySize, VZVirtualMachineConfiguration.minimumAllowedMemorySize);
    memorySize = MIN(memorySize, VZVirtualMachineConfiguration.maximumAllowedMemorySize);

    return memorySize;
}

+ (VZMacOSBootLoader *)createBootLoader
{
    return [[VZMacOSBootLoader alloc] init];
}

+ (VZMacGraphicsDeviceConfiguration *)createGraphicsDeviceConfiguration
{
    VZMacGraphicsDeviceConfiguration *graphicsConfiguration = [[VZMacGraphicsDeviceConfiguration alloc] init];
    graphicsConfiguration.displays = @[
        // We abitrarily choose the resolution of the display to be 1920 x 1200.
        [[VZMacGraphicsDisplayConfiguration alloc] initWithWidthInPixels:1920 heightInPixels:1200 pixelsPerInch:80],
    ];

    return graphicsConfiguration;
}

+ (VZVirtioBlockDeviceConfiguration *)createBlockDeviceConfigurationForDisk:(NSURL *)diskURL readOnly:(BOOL)ro
{
    NSError *error;
    VZDiskImageStorageDeviceAttachment *diskAttachment = [[VZDiskImageStorageDeviceAttachment alloc] initWithURL:diskURL readOnly:ro error:&error];
    if (!diskAttachment) {
        errx(1, "Failed to create VZDiskImageStorageDeviceAttachment: %s", [error.localizedDescription UTF8String]);
    }
    VZVirtioBlockDeviceConfiguration *disk = [[VZVirtioBlockDeviceConfiguration alloc] initWithAttachment:diskAttachment];

    return disk;
}

+ (VZVirtioNetworkDeviceConfiguration *)createNetworkDeviceConfiguration
{
    VZNATNetworkDeviceAttachment *natAttachment = [[VZNATNetworkDeviceAttachment alloc] init];
    VZVirtioNetworkDeviceConfiguration *networkConfiguration = [[VZVirtioNetworkDeviceConfiguration alloc] init];
    networkConfiguration.attachment = natAttachment;

    return networkConfiguration;
}

+ (VZUSBScreenCoordinatePointingDeviceConfiguration *)createPointingDeviceConfiguration
{
    return [[VZUSBScreenCoordinatePointingDeviceConfiguration alloc] init];
}

+ (VZUSBKeyboardConfiguration *)createKeyboardConfiguration
{
    return [[VZUSBKeyboardConfiguration alloc] init];
}

+ (VZVirtioSoundDeviceConfiguration *)createAudioDeviceConfiguration
{
    VZVirtioSoundDeviceConfiguration *audioDeviceConfiguration = [[VZVirtioSoundDeviceConfiguration alloc] init];

    VZVirtioSoundDeviceInputStreamConfiguration *inputStream = [[VZVirtioSoundDeviceInputStreamConfiguration alloc] init];
    inputStream.source = [[VZHostAudioInputStreamSource alloc] init];

    VZVirtioSoundDeviceOutputStreamConfiguration *outputStream = [[VZVirtioSoundDeviceOutputStreamConfiguration alloc] init];
    outputStream.sink = [[VZHostAudioOutputStreamSink alloc] init];

    audioDeviceConfiguration.streams = @[ inputStream, outputStream ];

    return audioDeviceConfiguration;
}

+ (VZMacPlatformConfiguration *)createMacPlatformConfigurationWithBundleDir:(NSString *)bundleDir
{
    if (![[NSFileManager defaultManager] fileExistsAtPath:bundleDir]) {
        errx(1, "Missing Virtual Machine Bundle at %s. Run InstallationTool first to create it.", [bundleDir UTF8String]);
    }

    VZMacPlatformConfiguration *macPlatformConfiguration = [[VZMacPlatformConfiguration alloc] init];
    NSURL *auxURL = [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"AuxiliaryStorage"]];
    VZMacAuxiliaryStorage *auxiliaryStorage = [[VZMacAuxiliaryStorage alloc] initWithContentsOfURL:auxURL];
    macPlatformConfiguration.auxiliaryStorage = auxiliaryStorage;

    // Retrieve the hardware model; you should save this value to disk
    // during installation.
    NSURL *modelURL = [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"HardwareModel"]];
    NSData *hardwareModelData = [[NSData alloc] initWithContentsOfURL:modelURL];
    if (!hardwareModelData) {
        errx(1, "Failed to retrieve hardware model data.");
    }

    VZMacHardwareModel *hardwareModel = [[VZMacHardwareModel alloc] initWithDataRepresentation:hardwareModelData];
    if (!hardwareModel) {
        errx(1, "Failed to create hardware model.");
    }

    if (!hardwareModel.supported) {
        errx(1, "The hardware model isn't supported on the current host");
    }
    macPlatformConfiguration.hardwareModel = hardwareModel;

    // Retrieve the machine identifier; you should save this value to disk
    // during installation.
    NSURL *idURL = [[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"MachineIdentifier"]];
    NSData *machineIdentifierData = [[NSData alloc] initWithContentsOfURL:idURL];
    if (!machineIdentifierData) {
        errx(1, "Failed to retrieve machine identifier data.");
    }

    VZMacMachineIdentifier *machineIdentifier = [[VZMacMachineIdentifier alloc] initWithDataRepresentation:machineIdentifierData];
    if (!machineIdentifier) {
        errx(1, "Failed to create machine identifier.");
    }
    macPlatformConfiguration.machineIdentifier = machineIdentifier;

    return macPlatformConfiguration;
}

+ (VZVirtualMachineConfiguration *)createBaseVirtualMachineConfigurationWithBundleDir:(NSString *)bundleDir
{
    VZVirtualMachineConfiguration *configuration = [VZVirtualMachineConfiguration new];

    configuration.platform = [self createMacPlatformConfigurationWithBundleDir:bundleDir];
    configuration.CPUCount = [self computeCPUCount];
    configuration.memorySize = [self computeMemorySize];
    configuration.bootLoader = [self createBootLoader];
    configuration.graphicsDevices = @[ [self createGraphicsDeviceConfiguration] ];
    NSURL *diskURL =[[NSURL alloc] initFileURLWithPath:[bundleDir stringByAppendingString:@"Disk.img"]];
    configuration.storageDevices = @[ [self createBlockDeviceConfigurationForDisk:diskURL readOnly:NO] ];
    configuration.networkDevices = @[ [self createNetworkDeviceConfiguration] ];
    configuration.pointingDevices = @[ [self createPointingDeviceConfiguration] ];
    configuration.keyboards = @[ [self createKeyboardConfiguration] ];
    configuration.audioDevices = @[ [self createAudioDeviceConfiguration] ];

    return configuration;
}

+ (VZVirtualMachine *)createVirtualMachineWithBundleDir:(NSString *)bundleDir
{
    VZVirtualMachineConfiguration *configuration = [self createBaseVirtualMachineConfigurationWithBundleDir:bundleDir];
    NSError *error;
    if (![configuration validateWithError:&error]) {
        errx(1, "Failed to validate configuration: %s", [error.localizedDescription UTF8String]);
    }

    return [[VZVirtualMachine alloc] initWithConfiguration:configuration];
}

+ (VZVirtualMachine *)createVirtualMachineWithBundleDir:(NSString *)bundleDir roDisk:(NSString *)roDisk
{
    VZVirtualMachineConfiguration *configuration = [self createBaseVirtualMachineConfigurationWithBundleDir:bundleDir];
    configuration.storageDevices = [configuration.storageDevices arrayByAddingObject:[self createBlockDeviceConfigurationForDisk:[[NSURL alloc] initFileURLWithPath:roDisk] readOnly:YES]];
    assert([configuration validateWithError:nil]);

    return [[VZVirtualMachine alloc] initWithConfiguration:configuration];
}

@end

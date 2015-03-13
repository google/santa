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

#include "SNTCommonEnums.h"

///
///  Singleton that provides an interface for managing configuration values on disk
///  @note This class is designed as a singleton but that is not enforced.
///
@interface SNTConfigurator : NSObject

///
///  The operating mode
///
@property santa_clientmode_t clientMode;

///
///  Whether or not to log all events, even for whitelisted binaries.
///
@property BOOL logAllEvents;

# pragma mark - Sync Settings

///
///  The base URL of the sync server
///
@property(readonly) NSURL *syncBaseURL;

///
///  The machine owner
///
@property(readonly) NSString *machineOwner;

///
///  If set, this over-rides the default machine ID used for syncing
///
@property(readonly) NSString *machineIDOverride;

# pragma mark Server Auth Settings

///
///  If set, this is valid PEM containing one or more certificates to be used to evaluate the
///  server's SSL chain, overriding the list of trusted CAs distributed with the OS.
///
@property(readonly) NSData *syncServerAuthRootsData;

///
///  This property is the same as the above but is a file on disk containing the PEM data.
///
@property(readonly) NSString *syncServerAuthRootsFile;

# pragma mark Client Auth Settings

///
///  If set, this contains the location of a PKCS#12 certificate to be used for sync authentication.
///
@property(readonly) NSString *syncClientAuthCertificateFile;

///
///  Contains the password for the pkcs#12 certificate.
///
@property(readonly) NSString *syncClientAuthCertificatePassword;

///
///  If set, this is the Common Name of a certificate in the System keychain to be used for
///  sync authentication. The corresponding private key must also be in the keychain.
///
@property(readonly) NSString *syncClientAuthCertificateCn;

///
///  If set, this is the Issuer Name of a certificate in the System keychain to be used for
///  sync authentication. The corresponding private key must also be in the keychain.
///
@property(readonly) NSString *syncClientAuthCertificateIssuer;

///
///  Retrieve an initialized singleton configurator object using the default file path
///
+ (instancetype)configurator;

///
///  Designated initializer
///
///  @param filePath The path to the file to use as a backing store.
///
- (instancetype)initWithFilePath:(NSString *)filePath;

@end

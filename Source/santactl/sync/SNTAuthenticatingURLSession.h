/// Copyright 2014 Google Inc. All rights reserved.
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

/// An authenticating NSURLSession, which can do both pinned verification of the SSL server
/// and handle client certificate authentication from the keychain.
@interface SNTAuthenticatingURLSession : NSObject<NSURLSessionDelegate>

/// The underlying session. Pass this session to NSURLRequest methods.
@property(readonly) NSURLSession *session;

/// If set, this is the user-agent to send with requests, otherwise remains the default
/// CFNetwork-based name.
@property(nonatomic) NSString *userAgent;

/// If set, the server that we connect to _must_ match this string. Redirects to other
/// hosts will not be allowed.
@property(nonatomic) NSString *serverHostname;

/// This should be PEM data containing one or more certificates to use to verify the server's
/// certificate chain. This will override the trusted roots in the System Roots.
@property(nonatomic) NSData *serverRootsPemData;

/// If set and client certificate authentication is needed, will search the keychain for a
/// certificate matching this common name and use that for authentication
/// @note: Not case sensitive
/// @note: If multiple matching certificates are found, the first one is used.
/// @note: If this property is not set and neither is |clientCertIssuerCn|, the allowed issuers
/// provided by the server will be used to find a matching certificate.
@property(nonatomic) NSString *clientCertCommonName;

/// If set and client certificate authentication is needed, will search the keychain for a
/// certificate issued by an issuer with this name and use that for authentication.
///
/// @note: Not case sensitive
/// @note: If multiple matching certificates are found, the first one is used.
/// @note: If this property is not set and neither is |clientCertCommonName|, the allowed issuers
/// provided by the server will be used to find a matching certificate.
@property(nonatomic) NSString *clientCertIssuerCn;

/// Designated initializer
- (instancetype)initWithSessionConfiguration:(NSURLSessionConfiguration *)configuration;

@end

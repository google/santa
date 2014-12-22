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

#import "SNTAuthenticatingURLSession.h"

#import "SNTCertificate.h"
#import "SNTConfigurator.h"
#import "SNTDERDecoder.h"
#import "SNTLogging.h"

@implementation SNTAuthenticatingURLSession

- (instancetype)initWithSessionConfiguration:(NSURLSessionConfiguration *)configuration {
  self = [super init];
  if (self) {
    _session = [NSURLSession sessionWithConfiguration:configuration
                                             delegate:self
                                        delegateQueue:nil];
  }
  return self;
}

- (instancetype)init {
  NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
  [config setTLSMinimumSupportedProtocol:kTLSProtocol12];
  [config setHTTPShouldUsePipelining:YES];
  return [self initWithSessionConfiguration:config];
}

#pragma mark User Agent property

- (NSString *)userAgent {
  return _session.configuration.HTTPAdditionalHeaders[@"User-Agent"];
}

- (void)setUserAgent:(NSString *)userAgent {
  NSMutableDictionary *addlHeaders = [_session.configuration.HTTPAdditionalHeaders mutableCopy];
  addlHeaders[@"User-Agent"] = userAgent;
  _session.configuration.HTTPAdditionalHeaders = addlHeaders;
}

#pragma mark NSURLSessionDelegate methods

- (void)URLSession:(NSURLSession *)session
    didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
      completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                  NSURLCredential *credential))completionHandler {
  NSURLProtectionSpace *protectionSpace = challenge.protectionSpace;

  if (challenge.previousFailureCount > 0) {
    completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
    return;
  }

  if (self.serverHostname && ![self.serverHostname isEqual:protectionSpace.host]) {
    completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
    return;
  }

  if (![protectionSpace.protocol isEqual:NSURLProtectionSpaceHTTPS]) {
    LOGD(@"Protection Space: %@ is not a secure protocol", protectionSpace.protocol);
    completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
    return;
  }

  if (!protectionSpace.receivesCredentialSecurely) {
    LOGD(@"Protection Space: secure authentication or protocol cannot be established");
    completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
    return;
  }

  NSString *authMethod = [protectionSpace authenticationMethod];

  if (authMethod == NSURLAuthenticationMethodClientCertificate) {
    NSURLCredential *cred = [self clientCredentialForProtectionSpace:protectionSpace];
    if (cred) {
      completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
      return;
    } else {
      LOGE(@"Servers asks for client authentication, no usable client certificates found.");
      completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
      return;
    }
  } else if (authMethod == NSURLAuthenticationMethodServerTrust) {
    NSURLCredential *cred = [self serverCredentialForProtectionSpace:protectionSpace];
    if (cred) {
      completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
      return;
    } else {
      LOGE(@"Servers asks for client authentication, no usable client certificates found.");
      completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
      return;
    }
  }

  completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

#pragma mark Private Helpers for URLSession:didReceiveChallenge:completionHandler:

/// Handles the process of locating a valid client certificate for authentication.
/// Operates in one of three modes, depending on the configuration in config.plist
///
/// Mode 1: if syncClientAuthCertificateCn is set, look for an identity in the keychain with a
///         matching common name and return it.
/// Mode 2: if syncClientAuthCertificateIssuer is set, look for an identity in the keychain with a
///         matching issuer common name and return it.
/// Mode 3: use the list of issuer details sent down by the server to find an identity in the
///         keychain.
///
/// If a valid identity cannot be found, returns nil.
- (NSURLCredential *)clientCredentialForProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
  __block OSStatus err = errSecSuccess;
  CFArrayRef cfIdentities = NULL;
  err = SecItemCopyMatching((__bridge CFDictionaryRef)@{
      (id)kSecClass : (id)kSecClassIdentity,
      (id)kSecReturnRef : @YES,
      (id)kSecMatchLimit : (id)kSecMatchLimitAll }, (CFTypeRef *)&cfIdentities);

  if (err != noErr) {
    LOGD(@"Client Trust: Failed to load client identities, SecItemCopyMatching returned: %d",
         (int)err);
    return nil;
  }
  NSArray *identities = CFBridgingRelease(cfIdentities);

  __block SecIdentityRef _foundIdentity;

  // Manually iterate through available identities to find one with an allowed issuer.
  [identities enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    SecIdentityRef identityRef = (__bridge SecIdentityRef)obj;

    SecCertificateRef certificate = NULL;
    err = SecIdentityCopyCertificate(identityRef, &certificate);
    if (err != errSecSuccess) {
      LOGD(@"Client Trust: Failed to read certificate data: %d. Skipping identity", (int)err);
      return;
    }

    SNTCertificate *clientCert = [[SNTCertificate alloc] initWithSecCertificateRef:certificate];
    CFRelease(certificate);

    // Switch identity finding method depending on config
    if (self.clientCertCommonName) {
      if ([clientCert.commonName compare:self.clientCertCommonName
                                 options:NSCaseInsensitiveSearch]) {
        LOGD(@"Client Trust: Valid client identity %@", clientCert);
        _foundIdentity = identityRef;
        CFRetain(_foundIdentity);
        *stop = YES;
        return;  // return from enumeration block
      }
    } else if (self.clientCertIssuerCn) {
      if ([clientCert.issuerCommonName compare:self.clientCertIssuerCn
                                       options:NSCaseInsensitiveSearch]) {
        LOGD(@"Client Trust: Valid client identity %@", clientCert);
        _foundIdentity = identityRef;
        CFRetain(_foundIdentity);
        *stop = YES;
        return;  // return from enumeration block
      }
    } else {
      for (NSData *allowedIssuer in protectionSpace.distinguishedNames) {
        SNTDERDecoder *decoder = [[SNTDERDecoder alloc] initWithData:allowedIssuer];
        if (!decoder) continue;
        if ([clientCert.issuerCommonName isEqual:decoder.commonName] &&
            [clientCert.issuerCountryName isEqual:decoder.countryName] &&
            [clientCert.issuerOrgName isEqual:decoder.organizationName] &&
            [clientCert.issuerOrgUnit isEqual:decoder.organizationalUnit]) {
          LOGD(@"Client Trust: Valid client identity %@", clientCert);
          _foundIdentity = identityRef;
          CFRetain(_foundIdentity);
          *stop = YES;
          return;  // return from enumeration block
        }
      }
    }
  }];

  if (_foundIdentity == NULL) {
    return nil;
  }

  return [NSURLCredential credentialWithIdentity:_foundIdentity
                                    certificates:nil
                                     persistence:NSURLCredentialPersistenceForSession];
}

/// Handles the process of evaluating the server's certificate chain.
/// Operates in one of three modes, depending on the configuration in config.plist
///
/// Mode 1: if syncServerAuthRootsData is set, evaluates the server's certificate chain contains
///         one of the certificates in the PEM data in the config plist.
/// Mode 2: if syncServerAuthRootsFile is set, evaluates the server's certificate chain contains
///         one of the certificates in the PEM data in the file specified.
/// Mode 3: evaluates the server's certificate chain is trusted by the keychain.
///
/// If the server's certificate chain does not evaluate for any reason, returns nil.
- (NSURLCredential *)serverCredentialForProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
  SecTrustRef serverTrust = protectionSpace.serverTrust;
  if (serverTrust == NULL) {
    LOGD(@"Server Trust: No server trust information available");
    return nil;
  }

  OSStatus err = errSecSuccess;

  if (self.serverRootsPemData) {
    NSString *pemStrings = [[NSString alloc] initWithData:self.serverRootsPemData
                                                 encoding:NSASCIIStringEncoding];
    NSArray *certs = [SNTCertificate certificatesFromPEM:pemStrings];

    // Make a new array of the SecCertificateRef's from the SNTCertificate's.
    NSMutableArray *certRefs = [[NSMutableArray alloc] initWithCapacity:certs.count];
    for (SNTCertificate *cert in certs) {
      [certRefs addObject:(id)cert.certRef];
    }

    // Set this array of certs as the anchors to trust.
    err = SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)certRefs);
    if (err != errSecSuccess) {
      LOGE(@"Server Trust: Could not set anchor certificates: %d");
      return nil;
    }
  }

  // Evaluate the server's cert chain.
  SecTrustResultType result = kSecTrustResultInvalid;
  err = SecTrustEvaluate(serverTrust, &result);
  if (err != errSecSuccess) {
    LOGE(@"Server Trust: Unable to evaluate certificate chain for server: %d", err);
    return nil;
  }

  // Print details about the server's leaf certificate.
  SecCertificateRef firstCert = SecTrustGetCertificateAtIndex(protectionSpace.serverTrust, 0);
  if (firstCert) {
    SNTCertificate *cert = [[SNTCertificate alloc] initWithSecCertificateRef:firstCert];
    LOGD(@"Server Trust: Server leaf cert: %@", cert);
  }

  // Having a trust level "unspecified" by the user is the usual result, described at
  // https://developer.apple.com/library/mac/qa/qa1360
  if (result != kSecTrustResultProceed && result != kSecTrustResultUnspecified) {
    LOGE(@"Server Trust: Server isn't trusted. SecTrustResultType: %d", result);
    return nil;
  }

  return [NSURLCredential credentialForTrust:serverTrust];
}

@end

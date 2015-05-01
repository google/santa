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

#import "SNTCodesignChecker.h"

#import <Security/Security.h>

#import "SNTCertificate.h"

/**
 *  kStaticSigningFlags are the flags used when validating signatures on disk.
 *
 *  Don't validate resources but do validate nested code. Ignoring resources _dramatically_ speeds
 *  up validation (see below) but does mean images, plists, etc will not be checked and modifying
 *  these will not be considered invalid. To ensure any code inside the binary is still checked,
 *  we check nested code.
 *
 *  Timings with different flags:
 *    Checking Xcode 5.1.1 bundle:
 *       kSecCSDefaultFlags:                                   3.895s
 *       kSecCSDoNotValidateResources:                         0.013s
 *       kSecCSDoNotValidateResources | kSecCSCheckNestedCode: 0.013s
 *
 *    Checking Google Chrome 36.0.1985.143 bundle:
 *       kSecCSDefaultFlags:                                   0.529s
 *       kSecCSDoNotValidateResources:                         0.032s
 *       kSecCSDoNotValidateResources | kSecCSCheckNestedCode: 0.033s
 */
static const SecCSFlags kStaticSigningFlags = kSecCSDoNotValidateResources | kSecCSCheckNestedCode;

/**
 *  kSigningFlags are the flags used when validating signatures for running binaries.
 *
 *  No special flags needed currently.
 */
static const SecCSFlags kSigningFlags = kSecCSDefaultFlags;

@interface SNTCodesignChecker ()
/// Array of @c SNTCertificate's representing the chain of certs this executable was signed with.
@property NSMutableArray *certificates;
@end

@implementation SNTCodesignChecker

#pragma mark Init/dealloc

- (instancetype)initWithSecStaticCodeRef:(SecStaticCodeRef)codeRef {
  self = [super init];

  if (self) {
    // First check the signing is valid
    if (CFGetTypeID(codeRef) == SecStaticCodeGetTypeID()) {
      if (SecStaticCodeCheckValidity(codeRef, kStaticSigningFlags, NULL) != errSecSuccess) {
        return nil;
      }
    } else if (CFGetTypeID(codeRef) == SecCodeGetTypeID()) {
      if (SecCodeCheckValidity((SecCodeRef)codeRef, kSigningFlags, NULL) != errSecSuccess) {
        return nil;
      }
    } else {
      return nil;
    }

    // Get CFDictionary of signing information for binary
    OSStatus status = errSecSuccess;
    CFDictionaryRef signingDict = NULL;
    status = SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation, &signingDict);
    _signingInformation = CFBridgingRelease(signingDict);
    if (status != errSecSuccess) return nil;

    // Get array of certificates.
    NSArray *certs = _signingInformation[(id)kSecCodeInfoCertificates];
    if (!certs) return nil;

    // Wrap SecCertificateRef objects in SNTCertificate and put in a new NSArray
    NSMutableArray *mutableCerts = [[NSMutableArray alloc] initWithCapacity:certs.count];
    for (NSUInteger i = 0; i < certs.count; ++i) {
      SecCertificateRef certRef = (__bridge SecCertificateRef)certs[i];
      SNTCertificate *newCert = [[SNTCertificate alloc] initWithSecCertificateRef:certRef];
      [mutableCerts addObject:newCert];
    }
    _certificates = [mutableCerts copy];

    _codeRef = codeRef;
    CFRetain(_codeRef);
  }

  return self;
}

- (instancetype)initWithBinaryPath:(NSString *)binaryPath {
  SecStaticCodeRef codeRef = NULL;

  // Get SecStaticCodeRef for binary
  if (SecStaticCodeCreateWithPath(
          (__bridge CFURLRef)[NSURL fileURLWithPath:binaryPath isDirectory:NO],
          kSecCSDefaultFlags,
          &codeRef) == errSecSuccess) {
    self = [self initWithSecStaticCodeRef:codeRef];
  } else {
    self = nil;
  }

  if (codeRef) CFRelease(codeRef);
  return self;
}

- (instancetype)initWithPID:(pid_t)PID {
  SecCodeRef codeRef = NULL;
  NSDictionary *attributes = @{ (__bridge NSString *)kSecGuestAttributePid : @(PID) };

  if (SecCodeCopyGuestWithAttributes(
          NULL,
          (__bridge CFDictionaryRef)attributes,
          kSecCSDefaultFlags,
          &codeRef) == errSecSuccess) {
    self = [self initWithSecStaticCodeRef:codeRef];
  } else {
    self = nil;
  }

  if (codeRef) CFRelease(codeRef);
  return self;
}

- (instancetype)initWithSelf {
  SecCodeRef codeSelf = NULL;
  if (SecCodeCopySelf(kSecCSDefaultFlags, &codeSelf) == errSecSuccess) {
    self = [self initWithSecStaticCodeRef:codeSelf];
  } else {
    self = nil;
  }

  if (codeSelf) CFRelease(codeSelf);
  return self;
}

- (instancetype)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (void)dealloc {
  if (_codeRef) {
    CFRelease(_codeRef);
    _codeRef = NULL;
  }
}

#pragma mark Description

- (NSString *)description {
  NSString *binarySource;
  if (CFGetTypeID(self.codeRef) == SecStaticCodeGetTypeID()) {
    binarySource = @"On-disk";
  } else {
    binarySource = @"In-memory";
  }

  return [NSString stringWithFormat:@"%@ binary, signed by %@, located at: %@",
              binarySource, self.leafCertificate.orgName, self.binaryPath];
}

#pragma mark Public accessors

- (SNTCertificate *)leafCertificate {
  return [self.certificates firstObject];
}

- (NSString *)binaryPath {
  CFURLRef path;
  OSStatus status = SecCodeCopyPath(self.codeRef, kSecCSDefaultFlags, &path);
  NSURL *pathURL = CFBridgingRelease(path);
  if (status != errSecSuccess) return nil;
  return [pathURL path];
}

- (BOOL)signingInformationMatches:(SNTCodesignChecker *)otherChecker {
  return [self.certificates isEqual:otherChecker.certificates];
}

@end

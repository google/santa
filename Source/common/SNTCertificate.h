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

///
///  SNTCertificate wraps a @c SecCertificateRef to provide Objective-C accessors to
///  commonly used certificate data. Accessors cache data for repeated access.
///
@interface SNTCertificate : NSObject<NSSecureCoding>

///
///  Initialize a SNTCertificate object with a valid SecCertificateRef. Designated initializer.
///
///  @param certRef valid SecCertificateRef, which will be retained.
///
- (instancetype)initWithSecCertificateRef:(SecCertificateRef)certRef;

///
///  Initialize a SNTCertificate object with certificate data in DER format.
///
///  @param certData DER-encoded certificate data.
///  @return initialized SNTCertificate or nil if certData is not a DER-encoded certificate.
///
- (instancetype)initWithCertificateDataDER:(NSData *)certData;

///
///  Initialize a SNTCertificate object with certificate data in PEM format.
///  If multiple PEM certificates exist within the string, the first is used.
///
///  @param certData PEM-encoded certificate data.
///  @return initialized SNTCertifcate or nil if certData is not a PEM-encoded certificate.
///
- (instancetype)initWithCertificateDataPEM:(NSString *)certData;

///
///  Returns an array of SNTCertificate's for all of the certificates in @c pemData.
///
///  @param pemData PEM-encoded certificates.
///  @return array of SNTCertificate objects.
///
+ (NSArray *)certificatesFromPEM:(NSString *)pemData;

///
///  Access the underlying certificate ref.
///
@property(readonly) SecCertificateRef certRef;

///
///  SHA-1 hash of the certificate data.
///
@property(readonly) NSString *SHA1;

///
///  SHA-256 hash of the certificate data.
///
@property(readonly) NSString *SHA256;

///
///  Certificate data.
///
@property(readonly) NSData *certData;

///
///  Common Name e.g: "Software Signing"
///
@property(readonly) NSString *commonName;

///
///  Country Name e.g: "US"
///
@property(readonly) NSString *countryName;

///
///  Organizational Name e.g: "Apple Inc."
///
@property(readonly) NSString *orgName;

///
///  Organizational Unit Name e.g: "Apple Software"
///
@property(readonly) NSString *orgUnit;

///
///  Issuer details, same fields as above.
///
@property(readonly) NSString *issuerCommonName;
@property(readonly) NSString *issuerCountryName;
@property(readonly) NSString *issuerOrgName;
@property(readonly) NSString *issuerOrgUnit;

///
///  Validity Not Before
///
@property(readonly) NSDate *validFrom;

///
///  Validity Not After
///
@property(readonly) NSDate *validUntil;

@end

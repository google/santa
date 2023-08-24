/// Copyright 2023 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/common/CertificateHelpers.h"

#include <Security/SecCertificate.h>

NSString *Publisher(NSArray<MOLCertificate *> *certs, NSString *teamID) {
  MOLCertificate *leafCert = [certs firstObject];

  if ([leafCert.commonName isEqualToString:@"Apple Mac OS Application Signing"]) {
    return [NSString stringWithFormat:@"App Store (Team ID: %@)", teamID];
  } else if (leafCert.commonName && leafCert.orgName) {
    return [NSString stringWithFormat:@"%@ - %@", leafCert.orgName, leafCert.commonName];
  } else if (leafCert.commonName) {
    return leafCert.commonName;
  } else if (leafCert.orgName) {
    return leafCert.orgName;
  } else {
    return nil;
  }
}

NSArray<id> *CertificateChain(NSArray<MOLCertificate *> *certs) {
  NSMutableArray *certArray = [NSMutableArray arrayWithCapacity:[certs count]];
  for (MOLCertificate *cert in certs) {
    [certArray addObject:(id)cert.certRef];
  }

  return certArray;
}

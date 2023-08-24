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

#ifndef SANTA__COMMON__CERTIFICATEHELPERS_H
#define SANTA__COMMON__CERTIFICATEHELPERS_H

#include <Foundation/Foundation.h>
#include <MOLCertificate/MOLCertificate.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/**
  Return a string representing publisher info from the provided certs

  @param certs A certificate chain
  @param teamID A team ID to be displayed for apps from the App Store

  @return A pretty string
*/
NSString *Publisher(NSArray<MOLCertificate *> *certs, NSString *teamID);

/**
  Return an array of the underlying SecCertificateRef's for the given array
  of MOLCertificates.

  @param certs An array of MOLCertificates

  @return An array of SecCertificateRefs. WARNING: If the refs need to be used
  for a long time be careful to properly CFRetain/CFRelease the returned items.
*/
NSArray<id> *CertificateChain(NSArray<MOLCertificate *> *certs);

__END_DECLS

#endif

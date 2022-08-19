/// Copyright 2022 Google Inc. All rights reserved.
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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_UTILITIES_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_UTILITIES_H

#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>

#include "Source/santad/EventProviders/EndpointSecurity/Message.h"

/**
  Sanitizes a given string if necessary, otherwise returns the original.
*/
NSString* sanitizeString(NSString* inStr);

/**

*/
es_file_t* GetAllowListTargetFile(
    const santa::santad::event_providers::endpoint_security::Message& msg);

#endif

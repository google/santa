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

#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"

#import "Source/common/SNTLogging.h"

using santa::santad::event_providers::endpoint_security::Message;

/**
  Sanitize the given C-string, replacing |, \n and \r characters.

  @return a new NSString with the replaced contents, if necessary, otherwise nil.
*/
static NSString* sanitizeCString(const char* str, NSUInteger length) {
  NSUInteger bufOffset = 0, strOffset = 0;
  char c = 0;
  char *buf = NULL;
  BOOL shouldFree = NO;

  if (length < 1) {
    return @"";
  }

  // Loop through the string one character at a time, looking for the characters
  // we want to remove.
  for (const char *p = str; (c = *p) != 0; ++p) {
    if (c == '|' || c == '\n' || c == '\r') {
      if (!buf) {
        // If string size * 6 is more than 64KiB use malloc, otherwise use stack space.
        if (length * 6 > 64 * 1024) {
          buf = (char*)malloc(length * 6);
          shouldFree = YES;
        } else {
          buf = (char*)alloca(length * 6);
        }
      }

      // Copy from the last offset up to the character we just found into the buffer
      ptrdiff_t diff = p - str;
      memcpy(buf + bufOffset, str + strOffset, diff - strOffset);

      // Update the buffer and string offsets
      bufOffset += diff - strOffset;
      strOffset = diff + 1;

      // Replace the found character and advance the buffer offset
      switch (c) {
        case '|':
          memcpy(buf + bufOffset, "<pipe>", 6);
          bufOffset += 6;
          break;
        case '\n':
          memcpy(buf + bufOffset, "\\n", 2);
          bufOffset += 2;
          break;
        case '\r':
          memcpy(buf + bufOffset, "\\r", 2);
          bufOffset += 2;
          break;
      }
    }
  }

  if (strOffset > 0 && strOffset < length) {
    // Copy any characters from the last match to the end of the string into the buffer.
    memcpy(buf + bufOffset, str + strOffset, length - strOffset);
    bufOffset += length - strOffset;
  }

  if (buf) {
    // Only return a new string if there were matches
    NSString *ret = [[NSString alloc] initWithBytes:buf
                                             length:bufOffset
                                           encoding:NSUTF8StringEncoding];
    if (shouldFree) {
      free(buf);
    }

    return ret;
  }
  return nil;
}

NSString* sanitizeString(NSString* inStr) {
  NSUInteger length = [inStr lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  if (length < 1) return inStr;

  NSString *ret = sanitizeCString([inStr UTF8String], length);
  if (ret) {
    return ret;
  }
  return inStr;
}

es_file_t* GetAllowListTargetFile(const Message& msg) {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
    return msg->event.close.target;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
      return msg->event.rename.source;
    default:
      // This is a programming error
      LOGE(@"Unexpected event type for AllowList");
      [NSException raise:@"Unexpected type"
                  format:@"Unexpected event type for AllowList: %d",
                         msg->event_type];
      return nil;
  }
}

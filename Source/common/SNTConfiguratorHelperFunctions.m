/// Copyright 2021 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

/**
 *
 * Helper function to split up a string of key value pairs separated by "="
 * (e.g. "a=b,c=d") into an NDictionary of @{@"key": @"value"};
 *
 * This trims whitespace from the start and end of each key value pair.
 *
 * Returns nil on error:
 *
 **/
NSDictionary *splitListOfKeyValuePairsSplitByEquals(NSString *configOption) {
  NSMutableDictionary *keyValuePairs = [[NSMutableDictionary alloc] init];

  // split string into parts by ","
  NSArray<NSString *> *entries = [configOption componentsSeparatedByString:@","];

  if (entries.count == 1 && [entries[0] isEqualToString:@""]) {
    return keyValuePairs;
  }

  // Split each entry string into two parts separated by an '='
  for (NSString *entry in entries) {
    NSArray<NSString *> *parts = [entry componentsSeparatedByString:@"="];
    if (parts.count != 2) {
      return nil;
    }

    NSString *key =
      [parts[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *value =
      [parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

    keyValuePairs[key] = value;
  }

  return keyValuePairs;
}

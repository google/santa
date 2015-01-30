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

#include "SNTLogging.h"

#import "SNTApplication.h"

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    // Do not buffer stdout
    setbuf(stdout, NULL);

    NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];

    if ([[[NSProcessInfo processInfo] arguments] containsObject:@"-v"]) {
      printf("%s\n", [infoDict[@"CFBundleVersion"] UTF8String]);
      return 0;
    }

    LOGI(@"Started, version %@", infoDict[@"CFBundleVersion"]);

    SNTApplication *s = [[SNTApplication alloc] init];
    [s performSelectorInBackground:@selector(run) withObject:nil];

    [[NSRunLoop mainRunLoop] run];
  }
}

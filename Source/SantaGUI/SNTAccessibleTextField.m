/// Copyright 2016 Google Inc. All rights reserved.
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

#import "Source/SantaGUI/SNTAccessibleTextField.h"

@implementation SNTAccessibleTextField

- (BOOL)accessibilityIsIgnored {
  return NO;
}

- (NSString *)accessibilityLabel {
  if (self.toolTip && self.stringValue) {
    return [NSString stringWithFormat:@"%@: %@", self.toolTip, self.stringValue];
  } else if (self.stringValue) {
    return self.stringValue;
  } else if (self.toolTip) {
    return self.toolTip;
  } else {
    return nil;
  }
}

- (NSString *)accessibilityRoleDescription {
  return @"label";
}

@end

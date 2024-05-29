/// Copyright 2024 Google LLC
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

#import "Source/common/SNTLogging.h"
#import "Source/common/SigningIDHelpers.h"

NSString *FormatSigningID(MOLCodesignChecker * csc) {
      if (csc.signingID) {
      	if (csc.platformBinary) {
        	return [NSString stringWithFormat:@"%@:%@", @"platform", csc.signingID];
      	} else if (csc.teamID) {
        	return [NSString stringWithFormat:@"%@:%@", csc.teamID, csc.signingID];
	} else {
		LOGE(@"unable to format signing ID missing team ID");
		return @"";
	}
      }
      LOGE(@"unable to format signing ID as it's missing");
      return @"";
}

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

#import "Source/common/Santa.pbobjc.h"
#import "Source/santad/Logs/SNTLogOutput.h"

NS_ASSUME_NONNULL_BEGIN

@interface SNTSimpleMaildir : NSObject<SNTLogOutput>

- (instancetype)initWithBaseDirectory:(NSString *)baseDirectory
                       filenamePrefix:(NSString *)filenamePrefix
                    fileSizeThreshold:(size_t)fileSiszeThreshold
               directorySizeThreshold:(size_t)directorySizeThreshold
                maxTimeBetweenFlushes:(NSTimeInterval)maxTimeBetweenFlushes
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

- (void)logEvent:(SNTSantaMessage *)message;
- (void)flush;

@end

NS_ASSUME_NONNULL_END


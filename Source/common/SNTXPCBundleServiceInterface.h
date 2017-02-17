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

@class SNTStoredEvent;

///  A block that takes the calculated bundle hash, associated events and hashing time in ms.
typedef void (^SNTBundleHashBlock)(NSString *, NSArray<SNTStoredEvent *> *, NSNumber *);

///  Protocol implemented by santabs and utilized by Santa GUI for bundle hashing
@protocol SNTBundleServiceXPC

///
///  @param listener The lister to connect back to the Santa GUI.
///
- (void)setBundleNotificationListener:(NSXPCListenerEndpoint *)listener;

///
///  Hash a bundle for an event. The SNTBundleHashBlock will be called with nil parameters if a
///  failure or cancelation occurs.
///
///  @param event The event that includes the fileBundlePath to be hashed.
///  @param reply A SNTBundleHashBlock to be executed upon completion or cancelation.
///
///  @note If there is a current NSProgress when called this method will report back it's progress.
///
- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event reply:(SNTBundleHashBlock)reply;

@end

@interface SNTXPCBundleServiceInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTBundleServiceXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning.
///
+ (NSXPCInterface *)bundleServiceInterface;

@end

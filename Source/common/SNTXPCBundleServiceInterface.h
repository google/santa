/// Copyright 2017 Google Inc. All rights reserved.
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

@import Foundation;

@class SNTStoredEvent;

///  A block that takes the calculated bundle hash, associated events and hashing time in ms.
typedef void (^SNTBundleHashBlock)(NSString *, NSArray<SNTStoredEvent *> *, NSNumber *);

///  Protocol implemented by santabs and utilized by SantaGUI for bundle hashing
@protocol SNTBundleServiceXPC

///
///  @param listener The listener to connect back to the SantaGUI.
///
- (void)setBundleNotificationListener:(NSXPCListenerEndpoint *)listener;

///
///  Hash a bundle for an event. The SNTBundleHashBlock will be called with nil parameters if a
///  failure or cancellation occurs.
///
///  @param event The event that includes the fileBundlePath to be hashed. This method will
///      attempt to to find and use the ancestor bundle as a starting point.
///  @param reply A SNTBundleHashBlock to be executed upon completion or cancellation.
///
///  @note If there is a current NSProgress when called this method will report back its progress.
///
- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event reply:(SNTBundleHashBlock)reply;

@end

@interface SNTXPCBundleServiceInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTBundleServiceXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning.
///
+ (NSXPCInterface *)bundleServiceInterface;

///
///  Returns the MachService ID for this service.
///
+ (NSString *)serviceId;

@end

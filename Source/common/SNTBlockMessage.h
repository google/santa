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

#ifdef SANTAGUI
@import Cocoa;
#else
@import Foundation;
#endif

@class SNTStoredEvent;

@interface SNTBlockMessage : NSObject

///
///  Return a message suitable for presenting to the user.
///  Uses either the configured message depending on the event type or a custom message
///  if the rule that blocked this file included one.
///
///  In SantaGUI this will return an NSAttributedString with links and formatting included
///  while for santad all HTML will be properly stripped.
///
+ (NSAttributedString *)attributedBlockMessageForEvent:(SNTStoredEvent *)event
                                         customMessage:(NSString *)customMessage;

///
///  Return a URL generated from the EventDetailURL configuration key
///  after replacing templates in the URL with values from the event.
///
+ (NSURL *)eventDetailURLForEvent:(SNTStoredEvent *)event;

///
///  Strip HTML from a string, replacing <br /> with newline.
///
+ (NSString *)stringFromHTML:(NSString *)html;

@end

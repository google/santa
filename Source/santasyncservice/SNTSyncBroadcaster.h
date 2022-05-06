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
///    limitations under the License

#import <Foundation/Foundation.h>

@class MOLXPCConnection;

// A small class to keep track of and send messages to active listeners.
@interface SNTSyncBroadcaster : NSObject

// Retrieve an initialized singleton SNTSyncBroadcaster object.
// Use this instead of init.
+ (instancetype)broadcaster;

- (void)addLogListener:(MOLXPCConnection *)logListener;
- (void)removeLogListener:(MOLXPCConnection *)logListener;
- (void)broadcastToLogListeners:(NSString *)log;

// Blocks until all the currently enqueued (up to this point) logs from -[broadcastToLogListeners:]
// are sent.
- (void)barrier;
@end

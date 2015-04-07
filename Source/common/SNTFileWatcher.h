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

///
///  Simple file watching class using dispatch sources. Will automatically
///  reload the watch if the file is deleted. Will continue watching for
///  events until deallocated.
///
@interface SNTFileWatcher : NSObject

///
///  Designated initializer
///  Initializes the watcher and begins watching for modifications.
///
///  @param filePath the file to watch.
///  @param handler the handler to call when changes happen.
///
///  @note Shortly after the file has been opened and monitoring has begun, the provided handler
///  will be called.
///
- (instancetype)initWithFilePath:(NSString *)filePath handler:(void (^)(void))handler;

@end

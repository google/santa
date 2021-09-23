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
#include <dispatch/dispatch.h>
#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>

#import "Source/santametricservice/Writers/SNTMetricHTTPWriter.h"

@implementation SNTMetricHTTPWriter {
 @private
  NSMutableURLRequest *_request;
  MOLAuthenticatingURLSession *_authSession;
  NSURLSession *_session;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _request = [[NSMutableURLRequest alloc] init];
    _request.HTTPMethod = @"POST";
    _authSession = [[MOLAuthenticatingURLSession alloc] init];
  }
  return self;
}

/**
 * Post serialzied metrics to the specified URL one object at a time.
 **/
- (BOOL)write:(NSArray<NSData *> *)metrics toURL:(NSURL *)url error:(NSError **)error {
  // open the file and write it.
  __block NSError *_blockError = nil;

  NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
  request.HTTPMethod = @"POST";
  [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

  _authSession.serverHostname = url.host;
  _session = _authSession.session;

  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    [metrics enumerateObjectsUsingBlock:^(id value, NSUInteger index, BOOL *stop) {
      request.HTTPBody = (NSData *)value;
      [[_session dataTaskWithRequest:request
                   completionHandler:^(NSData *_Nullable data, NSURLResponse *_Nullable response,
                                       NSError *_Nullable err) {
                     if (err != nil) {
                       _blockError = err;
                       *stop = YES;
                     }

                     if (response == nil) {
                       *stop = YES;
                     } else if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                       NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;

                       // Check HTTP error codes.
                       if (httpResponse && httpResponse.statusCode != 200) {
                         _blockError = [[NSError alloc]
                           initWithDomain:@"com.google.santa.metricservice.writers.http"
                                     code:httpResponse.statusCode
                                 userInfo:@{
                                   NSLocalizedDescriptionKey :
                                     [NSString stringWithFormat:@"received http status code %ld from %@",
                                                                httpResponse.statusCode, url]
                                 }];

                         *stop = YES;
                       }
                     }
                   }] resume];
    }];
    dispatch_semaphore_signal(semaphore);
  });

  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

  if (_blockError != nil) {
    if (error != nil) {
      *error = [_blockError copy];
    }
    return NO;
  }

  return YES;
}
@end

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
#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>
#include <dispatch/dispatch.h>

#import "Source/common/SNTLogging.h"
#import "Source/santametricservice/Writers/SNTMetricHTTPWriter.h"

@implementation SNTMetricHTTPWriter {
 @private
  MOLAuthenticatingURLSession *_authSession;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _authSession = [[MOLAuthenticatingURLSession alloc] init];
  }
  return self;
}

/**
 * Post serialzied metrics to the specified URL one object at a time.
 **/
- (BOOL)write:(NSArray<NSData *> *)metrics toURL:(NSURL *)url error:(NSError **)error {
  __block NSError *_blockError = nil;

  NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
  request.HTTPMethod = @"POST";
  [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

  _authSession.serverHostname = url.host;
  NSURLSession *_session = _authSession.session;

  dispatch_group_t requests = dispatch_group_create();

  [metrics enumerateObjectsUsingBlock:^(id value, NSUInteger index, BOOL *stop) {
    dispatch_group_enter(requests);

    request.HTTPBody = (NSData *)value;
    [[_session dataTaskWithRequest:request
                 completionHandler:^(NSData *_Nullable data, NSURLResponse *_Nullable response,
                                     NSError *_Nullable err) {
                   if (err != nil) {
                     _blockError = err;
                     *stop = YES;
                   } else if (response == nil) {
                     *stop = YES;
                   } else if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
                     NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;

                     // Check HTTP error codes and create errors for any non-200.
                     if (httpResponse && httpResponse.statusCode != 200) {
                       _blockError = [[NSError alloc]
                         initWithDomain:@"com.google.santa.metricservice.writers.http"
                                   code:httpResponse.statusCode
                               userInfo:@{
                                 NSLocalizedDescriptionKey : [NSString
                                   stringWithFormat:@"received http status code %ld from %@",
                                                    httpResponse.statusCode, url]
                               }];
                       *stop = YES;
                     }
                   }
                   dispatch_group_leave(requests);
                 }] resume];

    // Wait up to 30 seconds for the request to complete.
    if (dispatch_group_wait(requests, (int64_t)(30.0 * NSEC_PER_SEC)) != 0) {
      NSString *errMsg =
        [NSString stringWithFormat:@"HTTP request to %@ timed out after 30 seconds", url];

      _blockError = [[NSError alloc] initWithDomain:@"com.google.santa.metricservice.writers.http"
                                               code:ETIMEDOUT
                                           userInfo:@{NSLocalizedDescriptionKey : errMsg}];
    }
  }];

  if (_blockError != nil) {
    // If the caller hasn't passed us an error then we ignore it.
    if (error != nil) {
      *error = [_blockError copy];
    }

    return NO;
  }

  return YES;
}
@end

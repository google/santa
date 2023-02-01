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

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/santametricservice/Writers/SNTMetricHTTPWriter.h"

@interface SNTMetricHTTPWriter ()
@property SNTConfigurator *configurator;
@end

@implementation SNTMetricHTTPWriter

- (instancetype)init {
  self = [super init];
  if (self) {
    _configurator = [SNTConfigurator configurator];
  }
  return self;
}

- (MOLAuthenticatingURLSession *)createSessionWithHostname:(NSURL *)url
                                                   Timeout:(NSTimeInterval)timeout {
  NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
  config.TLSMinimumSupportedProtocolVersion = tls_protocol_version_TLSv12;
  config.HTTPShouldUsePipelining = YES;

  config.timeoutIntervalForRequest = timeout;
  config.timeoutIntervalForResource = timeout;

  MOLAuthenticatingURLSession *session =
    [[MOLAuthenticatingURLSession alloc] initWithSessionConfiguration:config];
  session.serverHostname = url.host;

  return session;
}

/**
 * Post serialzied metrics to the specified URL one object at a time.
 **/
- (BOOL)write:(NSArray<NSData *> *)metrics toURL:(NSURL *)url error:(NSError **)error {
  NSError *localError;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  MOLAuthenticatingURLSession *authSession =
    [self createSessionWithHostname:url Timeout:self.configurator.metricExportTimeout];

  NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
  request.HTTPMethod = @"POST";
  [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

  for (NSData *metric in metrics) {
    __block NSInteger savedStatusCode = 0;

    request.HTTPBody = (NSData *)metric;
    NSURLSessionDataTask *task = [authSession.session
      dataTaskWithRequest:request
        completionHandler:^(NSData *_Nullable data, NSURLResponse *_Nullable response,
                            NSError *_Nullable err) {
          if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            savedStatusCode = ((NSHTTPURLResponse *)response).statusCode;
          }
          dispatch_semaphore_signal(sema);
        }];

    [task resume];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

    // Note: localError will only store the last error that occured while
    // sending items from the array of metrics.
    if (task.error) {
      localError = task.error;
    } else if (savedStatusCode != 200) {
      localError = [[NSError alloc]
        initWithDomain:@"com.google.santa.metricservice.writers.http"
                  code:savedStatusCode
              userInfo:@{
                NSLocalizedDescriptionKey : [NSString
                  stringWithFormat:@"received http status code %ld from %@", savedStatusCode, url]
              }];
    }
  }

  if (error != nil) {
    *error = localError;
  }

  // Success is determined by whether or not any failures occured while sending
  // any of the metrics.
  return localError == nil;
}

@end

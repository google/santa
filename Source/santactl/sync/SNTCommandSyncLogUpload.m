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

#import "SNTCommandSyncLogUpload.h"

#import "NSData+Zlib.h"

#include "SNTLogging.h"

#import "SNTCommandSyncConstants.h"
#import "SNTCommandSyncState.h"
#import "SNTCommonEnums.h"

@implementation SNTCommandSyncLogUpload

+ (void)performSyncInSession:(NSURLSession *)session
                   syncState:(SNTCommandSyncState *)syncState
                  daemonConn:(SNTXPCConnection *)daemonConn
           completionHandler:(void (^)(BOOL success))handler {
  NSURL *url = syncState.uploadLogURL;
  NSMutableURLRequest *req = [[NSMutableURLRequest alloc] initWithURL:url];
  [req setHTTPMethod:@"POST"];
  NSString *boundary = @"----santa-sync-upload-boundary";

  NSString *contentType =
      [NSString stringWithFormat:@"multipart/form-data; charset=UTF-8; boundary=%@", boundary];
  [req setValue:contentType forHTTPHeaderField:@"Content-Type"];

  NSArray *logsToUpload = [self logsToUpload];

  // Upload the logs
  [[session uploadTaskWithRequest:req
                         fromData:[self requestBodyWithLogs:logsToUpload andBoundary:boundary]
                completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
      long statusCode = [(NSHTTPURLResponse *)response statusCode];
      if (statusCode != 200) {
        LOGE(@"HTTP Response: %ld %@",
             statusCode,
             [[NSHTTPURLResponse localizedStringForStatusCode:statusCode] capitalizedString]);
        LOGD(@"%@", error);
        handler(NO);
      } else {
        LOGI(@"Uploaded %lu logs", [logsToUpload count]);
        handler(YES);
      }
  }] resume];
}

+ (NSData *)requestBodyWithLogs:(NSArray *)logsToUpload andBoundary:(NSString *)boundary {
  // Prepare the body of the request, encoded as a multipart/form-data.
  // Along the way, gzip the individual log files and append .gz to their filenames.
  NSMutableData *reqBody = [[NSMutableData alloc] init];
  for (NSString *log in logsToUpload) {
    [reqBody appendData:
        [[NSString stringWithFormat:@"--%@\r\n", boundary] dataUsingEncoding:NSUTF8StringEncoding]];
    [reqBody appendData:
        [[NSString stringWithFormat:@"Content-Disposition: form-data; "
            @"name=\"%@\"; "
            @"filename=\"%@.gz\"\r\n", kLogUploadField, [log lastPathComponent]]
      dataUsingEncoding:NSUTF8StringEncoding]];
    [reqBody appendData:
        [@"Content-Type: application/x-gzip\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding]];
    [reqBody appendData:[[NSData dataWithContentsOfFile:log] gzipCompressed]];
    [reqBody appendData:[@"\r\n" dataUsingEncoding:NSUTF8StringEncoding]];
  }
  [reqBody appendData:
      [[NSString stringWithFormat:@"--%@--\r\n", boundary] dataUsingEncoding:NSUTF8StringEncoding]];

  return reqBody;
}

+ (NSArray *)logsToUpload {
  // General logs
  NSMutableArray *logsToUpload = [@[ @"/var/log/santa.log",
                                     @"/var/log/system.log" ] mutableCopy];

  // Kernel Panics, santad & santactl crashes
  NSString *diagsDir = @"/Library/Logs/DiagnosticReports/";
  NSDirectoryEnumerator *dirEnum = [[NSFileManager defaultManager] enumeratorAtPath:diagsDir];
  NSString *file;
  while (file = [dirEnum nextObject]) {
    if ([[file pathExtension] isEqualToString:@"panic"] ||
        [file hasPrefix:@"santad"] ||
        [file hasPrefix:@"santactl"]) {
      [logsToUpload addObject:[diagsDir stringByAppendingString:file]];
    }
  }

  return logsToUpload;
}

@end

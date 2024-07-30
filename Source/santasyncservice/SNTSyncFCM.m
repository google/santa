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

#import "Source/santasyncservice/SNTSyncFCM.h"

#import <Network/Network.h>

#import <MOLAuthenticatingURLSession/MOLAuthenticatingURLSession.h>

#ifdef DEBUG
#define LOGD(format, ...) NSLog(format, ##__VA_ARGS__);
#else  // DEBUG
#define LOGD(format, ...)
#endif  // DEBUG

/**  FCM checkin and register components */
static NSString *const kFCMCheckinHost = @"https://android.clients.google.com";
static NSString *const kFCMCheckin = @"/checkin";
static NSString *const kFCMCheckinBody = @"{'checkin':{}, 'version':3}";
static NSString *const kFCMRegister = @"/c2dm/register3";

/**  FCM connect and ack components */
static NSString *const kFCMConnectHost = @"https://fcmconnection.googleapis.com";
static NSString *const kFCMConnect = @"/v1alpha1:connectDownstream";
static NSString *const kFCMAck = @"/v1alpha1:ack";

/**  FCM client keys */
static NSString *const kAndroidIDKey = @"android_id";
static NSString *const kVersionInfoKey = @"version_info";
static NSString *const kSecurityTokenKey = @"security_token";

/**  HTTP Header Constants */
static NSString *const kFCMApplicationForm = @"application/x-www-form-urlencoded";
static NSString *const kFCMApplicationJSON = @"application/json";
static NSString *const kFCMContentType = @"Content-Type";

/**  Default 15 minute backoff maximum */
static const uint32_t kDefaultBackoffMaxSeconds = 900;

/**  Default 10 sec connect delay maximum */
static const uint32_t kDefaultConnectDelayMaxSeconds = 10;

#pragma mark MOLFCMClient Extension

@interface SNTSyncFCM () {
  /**  URL components for client registration, receiving and acknowledging messages. */
  NSURLComponents *_checkinComponents;
  NSURLComponents *_registerComponents;
  NSURLComponents *_connectComponents;
  NSURLComponents *_ackComponents;

  /**  Holds the NSURLSession object generated by the MOLAuthenticatingURLSession object. */
  NSURLSession *_session;

  /**  Holds the current backoff seconds. */
  uint32_t _backoffSeconds;

  /**  Holds the max connect and backoff seconds. */
  uint32_t _connectDelayMaxSeconds;
  uint32_t _backoffMaxSeconds;

  NSArray<NSNumber *> *_fatalHTTPStatusCodes;
}

/**  NSURLSession wrapper used for https communication with the FCM service. */
@property(nonatomic) MOLAuthenticatingURLSession *authSession;

/**  The block to be called for every message. */
@property(copy, nonatomic) SNTSyncFCMMessageHandler messageHandler;

/**  Is used throughout the class to reconnect to FCM after a connection loss. */
@property nw_path_monitor_t pathMonitor;

/**  FCM client identities. */
@property(nonatomic, readonly) NSString *project;
@property(nonatomic, readonly) NSString *entity;
@property(nonatomic, readonly) NSString *apiKey;

/**  FCM client checkin data */
@property NSString *androidID;
@property NSString *versionInfo;
@property NSString *securityToken;

/**  Called by the reachability handler when the host becomes reachable. */
- (void)reachabilityRestored;

@end

@implementation SNTSyncFCM

#pragma mark init/dealloc methods

- (instancetype)initWithProject:(NSString *)project
                         entity:(NSString *)entity
                         apiKey:(NSString *)apiKey
                connectDelayMax:(uint32_t)connectDelayMax
                     backoffMax:(uint32_t)backoffMax
                     fatalCodes:(NSArray<NSNumber *> *)fatalCodes
           sessionConfiguration:(NSURLSessionConfiguration *)sessionConfiguration
                 messageHandler:(SNTSyncFCMMessageHandler)messageHandler {
  self = [super init];
  if (self) {
    _project = project;
    _entity = entity;
    _apiKey = apiKey;
    _checkinComponents = [NSURLComponents componentsWithString:kFCMCheckinHost];
    _checkinComponents.path = kFCMCheckin;
    _registerComponents = [NSURLComponents componentsWithString:kFCMCheckinHost];
    _registerComponents.path = kFCMRegister;
    _connectComponents = [NSURLComponents componentsWithString:kFCMConnectHost];
    _connectComponents.path = kFCMConnect;
    _ackComponents = [NSURLComponents componentsWithString:kFCMConnectHost];
    _ackComponents.path = kFCMAck;

    _messageHandler = messageHandler;

    _authSession = [[MOLAuthenticatingURLSession alloc]
      initWithSessionConfiguration:sessionConfiguration
                                     ?: [NSURLSessionConfiguration defaultSessionConfiguration]];
    _authSession.dataTaskDidReceiveDataBlock = [self dataTaskDidReceiveDataBlock];
    _authSession.taskDidCompleteWithErrorBlock = [self taskDidCompleteWithErrorBlock];

    _session = _authSession.session;

    _connectDelayMaxSeconds = connectDelayMax ?: kDefaultConnectDelayMaxSeconds;
    _backoffMaxSeconds = backoffMax ?: kDefaultBackoffMaxSeconds;
    _fatalHTTPStatusCodes = fatalCodes ?: @[ @302, @400, @401, @403, @404 ];

    _pathMonitor = nw_path_monitor_create();
    nw_path_monitor_set_update_handler(_pathMonitor, ^(nw_path_t path) {
      dispatch_async(dispatch_get_main_queue(), ^{
        if (nw_path_get_status(path) == nw_path_status_satisfied) {
          SEL s = @selector(reachabilityRestored);
          [NSObject cancelPreviousPerformRequestsWithTarget:self selector:s object:nil];
          [self performSelector:s withObject:nil afterDelay:1];
        }
      });
    });
  }
  return self;
}

- (instancetype)initWithProject:(NSString *)project
                         entity:(NSString *)entity
                         apiKey:(NSString *)apiKey
           sessionConfiguration:(NSURLSessionConfiguration *)sessionConfiguration
                 messageHandler:(SNTSyncFCMMessageHandler)messageHandler {
  return [self initWithProject:project
                        entity:entity
                        apiKey:apiKey
               connectDelayMax:0
                    backoffMax:0
                    fatalCodes:nil
          sessionConfiguration:sessionConfiguration
                messageHandler:messageHandler];
}

- (instancetype)initWithProject:(NSString *)project
                         entity:(NSString *)entity
                         apiKey:(NSString *)apiKey
                 messageHandler:(SNTSyncFCMMessageHandler)messageHandler {
  return [self initWithProject:project
                        entity:entity
                        apiKey:apiKey
               connectDelayMax:0
                    backoffMax:0
                    fatalCodes:nil
          sessionConfiguration:nil
                messageHandler:messageHandler];
}

#pragma mark property methods

- (BOOL)isConnected {
  if (!self.androidID || !self.securityToken) return NO;
  for (NSURLSessionDataTask *dataTask in [self dataTasks]) {
    if (dataTask.state == NSURLSessionTaskStateRunning) return YES;
  }
  return NO;
}

#pragma mark reachability methods

- (void)reachabilityRestored {
  LOGD(@"Reachability restored. Reconnect after a backoff of %i seconds", _backoffSeconds);
  [self stopReachability];
  dispatch_time_t t = dispatch_time(DISPATCH_TIME_NOW, _backoffSeconds * NSEC_PER_SEC);
  dispatch_after(t, dispatch_get_main_queue(), ^{
    [self connectHelper];
  });
}

/**  Start listening for network state changes on a background thread. */
- (void)startReachability {
  LOGD(@"Reachability started.");
  nw_path_monitor_start(self.pathMonitor);
}

/**  Stop listening for network state changes. */
- (void)stopReachability {
  nw_path_monitor_cancel(self.pathMonitor);
}

#pragma mark message methods

- (void)connect {
  uint32_t ms = arc4random_uniform(_connectDelayMaxSeconds * 1000);
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, ms * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
    [self connectHelper];
  });
}

- (void)connectHelper {
  LOGD(@"Connecting...");
  [self cancelConnections];

  // Reuse checkin credentials / FCM token if allready registered.
  if (!self.androidID || !self.securityToken) return [self checkin];

  NSMutableURLRequest *URLRequest = [NSMutableURLRequest requestWithURL:_connectComponents.URL];
  [URLRequest addValue:kFCMApplicationJSON forHTTPHeaderField:kFCMContentType];
  URLRequest.HTTPMethod = @"GET";
  [self setCheckinAuthorization:URLRequest];
  [[_session dataTaskWithRequest:URLRequest] resume];
}

- (void)checkin {
  NSMutableURLRequest *URLRequest = [NSMutableURLRequest requestWithURL:_checkinComponents.URL];
  [URLRequest addValue:kFCMApplicationJSON forHTTPHeaderField:kFCMContentType];
  URLRequest.HTTPMethod = @"POST";
  URLRequest.HTTPBody = [kFCMCheckinBody dataUsingEncoding:NSUTF8StringEncoding];
  [[_session dataTaskWithRequest:URLRequest] resume];
}

- (void)checkinDataHandler:(NSData *)data {
  id jo = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
  LOGD(@"checkin: %@", jo);
  NSDictionary *checkin = [self extractCheckinFrom:jo];
  if (!checkin) return;
  self.androidID = [(NSNumber *)checkin[kAndroidIDKey] stringValue];
  self.versionInfo = checkin[kVersionInfoKey];
  self.securityToken = [(NSNumber *)checkin[kSecurityTokenKey] stringValue];
}

- (NSDictionary *)extractCheckinFrom:(id)jo {
  if (!jo) return nil;
  if (![jo isKindOfClass:[NSDictionary class]]) return nil;
  if (!jo[kAndroidIDKey]) return nil;
  if (![jo[kAndroidIDKey] isKindOfClass:[NSNumber class]]) return nil;
  if (!jo[kVersionInfoKey]) return nil;
  if (![jo[kVersionInfoKey] isKindOfClass:[NSString class]]) return nil;
  if (!jo[kSecurityTokenKey]) return nil;
  if (![jo[kSecurityTokenKey] isKindOfClass:[NSNumber class]]) return nil;
  return jo;
}

- (void)register {
  NSMutableURLRequest *URLRequest = [NSMutableURLRequest requestWithURL:_registerComponents.URL];
  URLRequest.HTTPMethod = @"POST";
  URLRequest.HTTPBody = [kFCMCheckinBody dataUsingEncoding:NSUTF8StringEncoding];
  NSURLComponents *params = [[NSURLComponents alloc] init];
  params.queryItems = @[
    [NSURLQueryItem queryItemWithName:@"app" value:self.project],
    [NSURLQueryItem queryItemWithName:@"info" value:self.versionInfo],
    [NSURLQueryItem queryItemWithName:@"sender" value:self.entity],
    [NSURLQueryItem queryItemWithName:@"device" value:self.androidID],
    [NSURLQueryItem queryItemWithName:@"X-scope" value:@"*"],
  ];
  URLRequest.HTTPBody = [params.query dataUsingEncoding:NSUTF8StringEncoding];
  [URLRequest addValue:kFCMApplicationForm forHTTPHeaderField:kFCMContentType];
  NSString *aid = [NSString stringWithFormat:@"AidLogin %@:%@", self.androidID, self.securityToken];
  [URLRequest addValue:aid forHTTPHeaderField:@"Authorization"];
  [[_session dataTaskWithRequest:URLRequest] resume];
}

- (void)registerDataHandler:(NSData *)data {
  NSString *t = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  NSArray *c = [t componentsSeparatedByString:@"="];
  if (c.count == 2) {
    NSString *tok = c[1];
    if ([tok isEqualToString:@"PHONE_REGISTRATION_ERROR"]) {
      LOGD(@"register: PHONE_REGISTRATION_ERROR - retrying");
      sleep(1);
      return [self register];
    }
    if (self.tokenHandler) self.tokenHandler(tok);
  }
}

- (void)acknowledgeMessage:(NSDictionary *)message {
  if (!message[@"messageId"]) return;
  NSMutableURLRequest *URLRequest = [NSMutableURLRequest requestWithURL:_ackComponents.URL];
  URLRequest.HTTPMethod = @"POST";
  [URLRequest addValue:kFCMApplicationJSON forHTTPHeaderField:kFCMContentType];
  [self setCheckinAuthorization:URLRequest];
  NSDictionary *b = @{@"ack" : @{@"messageId" : message[@"messageId"]}};
  NSData *body = [NSJSONSerialization dataWithJSONObject:b options:0 error:NULL];
  URLRequest.HTTPBody = body;
  [[_session dataTaskWithRequest:URLRequest
               completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                 if (((NSHTTPURLResponse *)response).statusCode != 200) {
                   if (self.acknowledgeErrorHandler) {
                     self.acknowledgeErrorHandler(message, error);
                   }
                 }
               }] resume];
}

- (void)disconnect {
  [self stopReachability];
  [_session invalidateAndCancel];
  _session = nil;
}

- (void)cancelConnections {
  for (NSURLSessionDataTask *dataTask in [self dataTasks]) {
    [dataTask cancel];
  }
}

- (NSArray<NSURLSessionDataTask *> *)dataTasks {
  __block NSArray *dataTasks;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [_session getTasksWithCompletionHandler:^(NSArray *data, NSArray *upload, NSArray *download) {
    dataTasks = data;
    dispatch_semaphore_signal(sema);
  }];
  dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
  return dataTasks;
}

/**
 *  Parse FCM data; extract and call self.messageHandler for each message.
 *
 *  Expected format:
 *   [{
 *     "noOp": {}
 *   }
 *   , <-- start of new chunk
 *   {
 *     "noOp": {}
 *   }
 *
 */
- (void)processMessagesFromData:(NSData *)data {
  if (!data) return;
  NSMutableString *raw = [[NSMutableString alloc] initWithData:data encoding:NSUTF8StringEncoding];
  if (raw.length < 2) return;
  // Add an opening bracket if this is a message in the middle of the stream.
  [raw replaceOccurrencesOfString:@",\r" withString:@"[" options:0 range:NSMakeRange(0, 2)];
  // Always add a closing bracket.
  [raw appendString:@"]"];
  NSError *err;
  id jo = [NSJSONSerialization JSONObjectWithData:[raw dataUsingEncoding:NSUTF8StringEncoding]
                                          options:0
                                            error:&err];
  if (!jo) {
    if (err) LOGD(@"processMessagesFromData err: %@", err);
    return;
  }
  LOGD(@"processMessagesFromData: %@", jo);

  if (![jo isKindOfClass:[NSArray class]]) return;
  for (id md in jo) {
    if (![md isKindOfClass:[NSDictionary class]]) continue;
    NSDictionary *m = md[@"message"];
    if ([m isKindOfClass:[NSDictionary class]]) self.messageHandler(m);
  }
}

- (void)handleHTTPReponse:(NSHTTPURLResponse *)HTTPResponse error:(NSError *)error {
  if (HTTPResponse.statusCode == 200) {
    _backoffSeconds = 0;
    if ([HTTPResponse.URL.path isEqualToString:kFCMCheckin]) {
      // If checkin was successful, start listening for messages and continue to register.
      [self connectHelper];
      return [self register];
    } else if ([HTTPResponse.URL.path isEqualToString:kFCMConnect]) {
      // connect will re-connect.
      return [self connectHelper];
    }  // register may be called more than once, don't do anything in response.
  } else if ([_fatalHTTPStatusCodes containsObject:@(HTTPResponse.statusCode)]) {
    if (self.connectionErrorHandler) self.connectionErrorHandler(HTTPResponse, error);
  } else {
    // If no backoff is set, start out with 5 - 15 seconds.
    // If a backoff is already set, double it, with a max of kBackoffMaxSeconds.
    _backoffSeconds = _backoffSeconds * 2 ?: arc4random_uniform(11) + 5;
    if (_backoffSeconds > _backoffMaxSeconds) _backoffSeconds = _backoffMaxSeconds;
    if (error) LOGD(@"handleHTTPReponse err: %@", error);
    [self startReachability];
  }
}

- (void)setCheckinAuthorization:(NSMutableURLRequest *)URLRequest {
  NSString *a = [NSString
    stringWithFormat:@"checkin %@:%@ %@", self.androidID, self.securityToken, self.versionInfo];
  [URLRequest addValue:a forHTTPHeaderField:@"Authorization"];
  [URLRequest addValue:self.apiKey forHTTPHeaderField:@"X-Goog-Api-Key"];
}

#pragma mark NSURLSession block property and methods

/**
 *  MOLAuthenticatingURLSession is the NSURLSessionDelegate. It will call this block every time
 *  the URLSession:task:didCompleteWithError: is called. This allows MOLFCMClient to be notified
 *  when a task ends while using delegate methods.
 */
- (void (^)(NSURLSession *, NSURLSessionDataTask *, NSData *))dataTaskDidReceiveDataBlock {
  __weak __typeof(self) weakSelf = self;
  return ^(NSURLSession *session, NSURLSessionDataTask *dataTask, NSData *data) {
    __typeof(self) strongSelf = weakSelf;
    NSString *path = dataTask.originalRequest.URL.path;
    if ([path isEqualToString:kFCMCheckin]) {
      return [strongSelf checkinDataHandler:data];
    } else if ([path isEqualToString:kFCMRegister]) {
      return [strongSelf registerDataHandler:data];
    } else if ([dataTask.originalRequest.URL.path isEqualToString:kFCMConnect]) {
      [strongSelf processMessagesFromData:data];
    }
  };
}

/**
 *  MOLAuthenticatingURLSession is the NSURLSessionDataDelegate. It will call this block every time
 *  the URLSession:dataTask:didReceiveData: is called. This allows for message data chunks to be
 *  processed as they appear in the FCM buffer. For Content-Type: text/html there is a 512 byte
 *  buffer that must be filled before data is returned. Content-Type: application/json does not use
 *  a buffer and data is returned as soon as it is available.
 *
 *  TODO:(bur) Follow up with FCM on Content-Type: application/json. Currently FCM returns data with
 *  Content-Type: text/html. Messages under 512 bytes will not be processed until the connection
 *  drains.
 */
- (void (^)(NSURLSession *, NSURLSessionTask *, NSError *))taskDidCompleteWithErrorBlock {
  __weak __typeof(self) weakSelf = self;
  return ^(NSURLSession *session, NSURLSessionTask *task, NSError *error) {
    __typeof(self) strongSelf = weakSelf;
    // task.response can be nil when an NSURLError* occurs
    if (task.response && ![task.response isKindOfClass:[NSHTTPURLResponse class]]) {
      if (strongSelf.connectionErrorHandler) strongSelf.connectionErrorHandler(nil, error);
      return;
    }
    NSHTTPURLResponse *HTTPResponse = (NSHTTPURLResponse *)task.response;
    [strongSelf handleHTTPReponse:HTTPResponse error:error];
  };
}

@end

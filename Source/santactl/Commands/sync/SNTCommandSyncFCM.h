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

#import <Foundation/Foundation.h>

/**  A block that takes a NSString object as an argument. */
typedef void (^SNTCommandSyncFCMTokenHandler)(NSString *);

/**  A block that takes a NSDictionary object as an argument. */
typedef void (^SNTCommandSyncFCMMessageHandler)(NSDictionary *);

/**  A block that takes a NSHTTPURLResponse and NSError object as an argument. */
typedef void (^SNTCommandSyncFCMConnectionErrorHandler)(NSHTTPURLResponse *, NSError *);

/**  A block that takes a NSDictionary and NSError object as arguments. */
typedef void (^SNTCommandSyncFCMAcknowledgeErrorHandler)(NSDictionary *, NSError *);

@interface SNTCommandSyncFCM : NSObject

/**  Returns YES if connected to FCM. */
@property(readonly, nonatomic) BOOL isConnected;

/**  A block to be executed when the FCM token changes */
@property(copy) SNTCommandSyncFCMTokenHandler tokenHandler;

/**  A block to be executed when there is an issue with acknowledging a message. */
@property(copy) SNTCommandSyncFCMAcknowledgeErrorHandler acknowledgeErrorHandler;

/**  A block to be executed when there is a non-recoverable issue with the FCM Connection. */
@property(copy) SNTCommandSyncFCMConnectionErrorHandler connectionErrorHandler;

- (instancetype)init NS_UNAVAILABLE;

/**
 *  The designated initializer.
 *
 *  @param project FCM project
 *  @param entity FCM entity
 *  @param apiKey FCM apiKey
 *  @param connectDelayMax Optional, max delay (seconds) when calling connect
 *  @param backoffMax Optional, max backoff (seconds) when the connection is interrupted
 *  @param fatalCodes Optional, do not attempt to reconnect if a fatal code is returned
 *  @param sessionConfiguration Optional, the desired NSURLSessionConfiguration
 *  @param messageHandler The block to be called for every message received
 *
 *  @note If the host argument is nil, https://fcm-stream.googleapis.com will be used.
 *  @note If the connectDelayMax argument is 0, a default value of 10 will be used.
 *  @note If the backoffMax argument is 0, a default value of 900 will be used.
 *  @note If the fatalCodes argument is nil, @[@302, @400, @403] will be used.
 *  @note If the sessionConfiguration argument is nil, defaultSessionConfiguration will be used.
 *
 *  @return An initialized SNTCommandSyncFCM object
 */
- (instancetype)initWithProject:(NSString *)project
                         entity:(NSString *)entity
                         apiKey:(NSString *)apiKey
                connectDelayMax:(uint32_t)connectDelayMax
                     backoffMax:(uint32_t)backoffMax
                     fatalCodes:(NSArray<NSNumber *> *)fatalCodes
           sessionConfiguration:(NSURLSessionConfiguration *)sessionConfiguration
                 messageHandler:(SNTCommandSyncFCMMessageHandler)messageHandler
    NS_DESIGNATED_INITIALIZER;

/**  A convenience initializer. Optional args will use their zero values. */
- (instancetype)initWithProject:(NSString *)project
                         entity:(NSString *)entity
                         apiKey:(NSString *)apiKey
           sessionConfiguration:(NSURLSessionConfiguration *)sessionConfiguration
                 messageHandler:(SNTCommandSyncFCMMessageHandler)messageHandler;

/**  A convenience initializer. Optional args will use their zero values. */
- (instancetype)initWithProject:(NSString *)project
                         entity:(NSString *)entity
                         apiKey:(NSString *)apiKey
                 messageHandler:(SNTCommandSyncFCMMessageHandler)messageHandler;

/**
 *  Opens a connection to FCM and starts listening for messages.
 *
 *  @note A random delay will occur before the connection is made.
 *  @note If there is a failure in the connection, reconnection will occur once FCM is reachable.
 *        Failed reconnections will backoff exponentially up to the defined max.
 */
- (void)connect;

/**
 *  Acknowledges a FCM message. Each message received must be acknowledged.
 *
 *  @param message A FCM message
 *
 *  @note Calls the acknowledgeErrorHandler block property when an acknowledge error occurs.
 */
- (void)acknowledgeMessage:(NSDictionary *)message;

/**
 *  Closes all FCM connections. Stops Reachability. Outstanding tasks will be canceled.
 *
 *  @note After disconnect is called the receiver is considered dead. A new MOLFCMClient object
 *        will need to be created to begin listening for messages.
 *  @note After disconnect the receiver can hold a reference to itself for up to 15 minutes.
 */
- (void)disconnect;

@end

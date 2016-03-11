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

/**
  A wrapper around NSXPCListener and NSXPCConnection to provide client multiplexing, signature
  validation of connecting clients and a simpler interface.

  Example server started by @c launchd where the @c launchd job has a @c MachServices key:

  @code
   SNTXPCConnection *conn = [[SNTXPCConnection alloc] initServerWithName:@"MyServer"];
   conn.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyServerProtocol)];
   conn.exportedObject = myObject;
   [conn resume];
  @endcode

  Example client, connecting to above server:

  @code
   SNTXPCConnection *conn = [[SNTXPCConnection alloc] initClientWithName:"MyServer"
                                                             withOptions:0];
   conn.remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyServerProtocol)];
   conn.invalidationHandler = ^{ NSLog(@"Connection invalidated") };
   [conn resume];
  @endcode

  The client can send a message to the server with:

  @code
   [conn.remoteObjectProxy selectorInRemoteInterface];
  @endcode
 
  @note messages are always delivered on a background thread!
*/
@interface SNTXPCConnection : NSObject<NSXPCListenerDelegate>

/**
  Initialize a new server with a given listener, provided by `[NSXPCListener anonymousListener]`.
*/
- (instancetype)initServerWithListener:(NSXPCListener *)listener;

/**
  Initializer for the 'server' side of the connection, started by launchd.

  @param name MachService name, must match the MachServices key in the launchd.plist
*/
- (instancetype)initServerWithName:(NSString *)name;

/**
  Initializer a new client to a service exported by a LaunchDaemon.

  @param name MachService name
  @param privileged Use YES if the server is running as root.
*/
- (instancetype)initClientWithName:(NSString *)name privileged:(BOOL)privileged;

/**
  Initialize a new client with a listener endpoint sent from another process.

  @param listener An NSXPCListenerEndpoint to connect to.
*/
- (instancetype)initClientWithListener:(NSXPCListenerEndpoint *)listener;

/**
  Call when the properties of the object have been set-up and you're ready for connections.
*/
- (void)resume;

/**
  Invalidate the connection(s). This must be done before the object can be released.
*/
- (void)invalidate;

/**
  The interface the remote object should conform to. (client)
 */
@property(retain) NSXPCInterface *remoteInterface;

/**
  A proxy to the object at the other end of the connection. (client)
 */
@property(readonly, nonatomic) id remoteObjectProxy;

/**
  The interface this object exports. (server)
 */
@property(retain) NSXPCInterface *exportedInterface;

/**
  The object that responds to messages from the other end. (server)
 */
@property(retain) id exportedObject;

/**
  A block to run when a/the connection is invalidated/interrupted.
 */
@property(copy) void (^invalidationHandler)(void);

@end

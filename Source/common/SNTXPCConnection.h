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
  validation of connecting clients and forced connection establishment.

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

  One advantage of the way that SNTXPCConnection works over using NSXPCConnection directly is that
  from the client-side once the resume method has finished, the connection is either valid or the
  invalidation handler will be called. Ordinarily, the connection doesn't actually get made until
  the first message is sent across it.

  @note messages are always delivered on a background thread!
*/
@interface SNTXPCConnection : NSObject<NSXPCListenerDelegate>

/**
  Initialize a new server with a given listener, provided by `[NSXPCListener anonymousListener]`.
*/
- (nullable instancetype)initServerWithListener:(nonnull NSXPCListener *)listener;

/**
  Initializer for the 'server' side of the connection, started by launchd.

  @param name MachService name, must match the MachServices key in the launchd.plist
*/
- (nullable instancetype)initServerWithName:(nonnull NSString *)name;

/**
  Initializer a new client to a service exported by a LaunchDaemon.

  @param name MachService name
  @param privileged Use YES if the server is running as root.
*/
- (nullable instancetype)initClientWithName:(nonnull NSString *)name privileged:(BOOL)privileged;

/**
  Initialize a new client with a listener endpoint sent from another process.

  @param listener An NSXPCListenerEndpoint to connect to.
*/
- (nullable instancetype)initClientWithListener:(nonnull NSXPCListenerEndpoint *)listener;

/**
  Call when the properties of the object have been set-up and you're ready for connections.

  For clients, this call can take up to 2s to complete for connection to finish establishing though
  in basically all cases it will actually complete in a few milliseconds.
*/
- (void)resume;

/**
  Invalidate the connection(s). This must be done before the object can be released.
*/
- (void)invalidate;

/**
  The interface the remote object should conform to. (client)
*/
@property(retain, nullable) NSXPCInterface *remoteInterface;

/**
  A proxy to the object at the other end of the connection. (client)

  @note If the connection to the server failed, this will be nil, so you can safely send messages
  and rely on the invalidationHandler for handling the failure.
*/
@property(readonly, nonatomic, nullable) id remoteObjectProxy;

/**
  The interface this object exports. (server)
*/
@property(retain, nullable) NSXPCInterface *exportedInterface;

/**
  The object that responds to messages from the other end. (server)
*/
@property(retain, nullable) id exportedObject;

/**
  A block to run when a/the connection is accepted and fully established.
*/
@property(copy, nullable) void (^acceptedHandler)(void);

/**
  A block to run when a/the connection is invalidated/interrupted/rejected.
*/
@property(copy, nullable) void (^invalidationHandler)(void);

@end

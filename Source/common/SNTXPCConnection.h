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
///  A validating XPC connection/listener which uses codesigning to validate that both ends of the
///  connection were signed by the same certificate chain.
///
///  Example server started by @c launchd where the @c launchd job has a @c MachServices key:
///
/// @code
///   SNTXPCConnection *conn = [[SNTXPCConnection alloc] initServerWithName:@"MyServer"];
///   conn.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyServerProtocol)];
///   conn.exportedObject = myObject;
///   conn.remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyClientProtocol)];
///   [conn resume];
/// @endcode
///
///  Example client, connecting to above server:
///
/// @code
///  SNTXPCConnection *conn = [[SNTXPCConnection alloc] initClientWithName:"MyServer"
///                                                            withOptions:0];
///  conn.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyClientProtocol)];
///  conn.exportedObject = myObject;
///  conn.remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyServerProtocol)];
///  conn.invalidationHandler = ^{ NSLog(@"Connection invalidated") };
///  [conn resume];
/// @endcode
///
///  Either side can then send a message to the other with:
///
/// @code
///  [conn.remoteObjectProxy selectorInRemoteInterface];
/// @endcode
///
///  @note messages are always delivered on a background thread!
///
@interface SNTXPCConnection : NSObject<NSXPCListenerDelegate>

typedef void (^SNTXPCInvalidationBlock)(void);
typedef void (^SNTXPCAcceptedBlock)(void);
typedef void (^SNTXPCRejectedBlock)(void);

///
///  The interface the remote object should conform to.
///
@property(retain) NSXPCInterface *remoteInterface;

///
///  A proxy to the object at the other end of the connection.
///
///  @warning Do not send a message to this object if you didn't set @c remoteInterface above
///  before calling the @c resume method. Doing so will throw an exception.
///
@property(readonly, nonatomic) id remoteObjectProxy;

///
///  The interface this object exports.
///
@property(retain) NSXPCInterface *exportedInterface;

///
///  The object that responds to messages from the other end.
///
@property(retain) id exportedObject;

///
///  A block to run when the connection is invalidated.
///
@property(copy) SNTXPCInvalidationBlock invalidationHandler;

///
///  A block to run when the connection has been accepted.
///
@property(copy) SNTXPCAcceptedBlock acceptedHandler;

///
///  A block to run when the connection has been rejected.
///
@property(copy) SNTXPCRejectedBlock rejectedHandler;

///
///  Initializer for the 'server' side of the connection, the binary that was started by launchd.
///
///  @param name MachService name
///
- (instancetype)initServerWithName:(NSString *)name;

///
///  Initializer for the 'client' side of the connection.
///
///  @param name MachService name
///  @param options Use NSXPCConnectionPrivileged if the server is running as root, otherwise use 0.
///
- (instancetype)initClientWithName:(NSString *)name options:(NSXPCConnectionOptions)options;

///
///  Call when the properties of the object have been set-up and you're ready for connections.
///  Blocks the executing thread for up to 5s while waiting for the verification to complete.
///
- (void)resume;

///
///  Invalidate the connection. This must be done before the connection can be released.
///
- (void)invalidate;

@end

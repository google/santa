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

#import "SNTXPCConnection.h"

#import "MOLCodesignChecker.h"

#import "SNTStrengthify.h"

/**
  Protocol used during connection establishment, @see SNTXPCConnectionInterface
*/
@protocol SNTXPCConnectionProtocol
- (void)connectWithReply:(void (^)())reply;
@end

/**
  Recipient object used during connection establishment. Each incoming connection
  has one of these objects created which accept the message in the protocol
  and call the block provided during creation before replying.

  This allows the server to reset the connection's exported interface and
  object to the correct values after the client has sent the establishment message.
*/
@interface SNTXPCConnectionInterface : NSObject<SNTXPCConnectionProtocol>
@property(strong) void (^block)(void);
@end

@implementation SNTXPCConnectionInterface
- (void)connectWithReply:(void (^)())reply {
  if (self.block) self.block();
  reply();
}
@end

@interface SNTXPCConnection ()
@property NSXPCInterface *validationInterface;

/// The XPC listener (server only).
@property NSXPCListener *listenerObject;

/// The current connection object (client only).
@property NSXPCConnection *currentConnection;
@end

@implementation SNTXPCConnection

#pragma mark Initializers

- (instancetype)initServerWithListener:(NSXPCListener *)listener {
  self = [super init];
  if (self) {
    _listenerObject = listener;
    _validationInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(SNTXPCConnectionProtocol)];
  }
  return self;
}

- (instancetype)initServerWithName:(NSString *)name {
  return [self initServerWithListener:[[NSXPCListener alloc] initWithMachServiceName:name]];
}

- (instancetype)initClientWithListener:(NSXPCListenerEndpoint *)listener {
  self = [super init];
  if (self) {
    _currentConnection = [[NSXPCConnection alloc] initWithListenerEndpoint:listener];
    if (!_currentConnection) return nil;
    _validationInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(SNTXPCConnectionProtocol)];
  }
  return self;
}

- (instancetype)initClientWithName:(NSString *)name privileged:(BOOL)privileged {
  self = [super init];
  if (self) {
    NSXPCConnectionOptions options = (privileged ? NSXPCConnectionPrivileged : 0);
    _currentConnection = [[NSXPCConnection alloc] initWithMachServiceName:name options:options];
    if (!_currentConnection) return nil;
    _validationInterface =
        [NSXPCInterface interfaceWithProtocol:@protocol(SNTXPCConnectionProtocol)];
  }
  return self;
}

- (instancetype)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

#pragma mark Connection set-up

- (void)resume {
  if (self.listenerObject) {
    self.listenerObject.delegate = self;
    [self.listenerObject resume];
  } else {
    WEAKIFY(self);

    // Set-up the connection with the remote interface set to the validation interface,
    // send a message to the listener to finish establishing the connection
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    self.currentConnection.remoteObjectInterface = self.validationInterface;
    self.currentConnection.interruptionHandler = self.invalidationHandler;
    self.currentConnection.invalidationHandler = self.invalidationHandler;
    [self.currentConnection resume];
    [[self.currentConnection remoteObjectProxy] connectWithReply:^{
      STRONGIFY(self);
      // The connection is now established
      [self.currentConnection suspend];
      self.currentConnection.remoteObjectInterface = self.remoteInterface;
      [self.currentConnection resume];
      dispatch_semaphore_signal(sema);
      if (self.acceptedHandler) self.acceptedHandler();
    }];
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC))) {
      // Connection was not established in a reasonable time, invalidate.
      self.currentConnection.remoteObjectInterface = nil;  // ensure clients don't try to use it.
      [self.currentConnection invalidate];
    }
  }
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
  pid_t pid = connection.processIdentifier;
  MOLCodesignChecker *otherCS = [[MOLCodesignChecker alloc] initWithPID:pid];
  if (![otherCS signingInformationMatches:[[MOLCodesignChecker alloc] initWithSelf]]) {
    return NO;
  }

  // The client passed the code signature check, now we need to resume the listener and
  // return YES so that the client can send the connectWithReply message. Once the client does
  // we reset the connection's exportedInterface and exportedObject.
  SNTXPCConnectionInterface *ci = [[SNTXPCConnectionInterface alloc] init];
  WEAKIFY(self);
  WEAKIFY(connection);
  ci.block = ^{
    STRONGIFY(self)
    STRONGIFY(connection);
    [connection suspend];
    connection.invalidationHandler = connection.interruptionHandler = ^{
      if (self.invalidationHandler) self.invalidationHandler();
    };
    connection.exportedInterface = self.exportedInterface;
    connection.exportedObject = self.exportedObject;
    [connection resume];

    // The connection is now established.
    if (self.acceptedHandler) self.acceptedHandler();
  };
  connection.exportedInterface = self.validationInterface;
  connection.exportedObject = ci;
  [connection resume];

  return YES;
}

- (id)remoteObjectProxy {
  if (self.currentConnection.remoteObjectInterface &&
      self.currentConnection.remoteObjectInterface != self.validationInterface) {
    return [self.currentConnection remoteObjectProxyWithErrorHandler:^(NSError *error) {
      [self.currentConnection invalidate];
    }];
  }
  return nil;
}

#pragma mark Connection tear-down

- (void)invalidate {
  if (self.currentConnection) {
    [self.currentConnection invalidate];
    self.currentConnection = nil;
  } else if (self.listenerObject) {
    [self.listenerObject invalidate];
  }
}

@end

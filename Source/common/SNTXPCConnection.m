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

@interface SNTXPCConnectionValidator : NSObject
@property NSXPCConnection *connection;
@property(copy) SNTXPCAcceptedBlock acceptedHandler;
@property(copy) SNTXPCRejectedBlock rejectedHandler;
@end

@implementation SNTXPCConnectionValidator

- (void)isConnectionValidWithBlock:(void (^)(BOOL))block {
  pid_t pid = self.connection.processIdentifier;

  MOLCodesignChecker *selfCS = [[MOLCodesignChecker alloc] initWithSelf];
  MOLCodesignChecker *otherCS = [[MOLCodesignChecker alloc] initWithPID:pid];

  if ([otherCS signingInformationMatches:selfCS]) {
    [self.connection suspend];
    // It's expected that the acceptedHandler will set these but just in case,
    // we reset them to nil.
    self.connection.remoteObjectInterface = nil;
    self.connection.exportedInterface = nil;
    self.connection.exportedObject = nil;
    self.acceptedHandler();
    [self.connection resume];

    // Let remote end know that we accepted. In acception this must come last otherwise
    // the remote end might start sending messages before the interface is fully set-up.
    block(YES);
  } else {
    // Let remote end know that we rejected. In rejection this must come first otherwise
    // the connection is invalidated before the client ever realizes.
    block(NO);

    self.rejectedHandler();

    [self.connection invalidate];
    self.connection = nil;
  }
}

@end

@protocol XPCConnectionValidityRequest
- (void)isConnectionValidWithBlock:(void (^)(BOOL))block;
@end

@interface SNTXPCConnection ()

///
/// The XPC listener (used on server-side only).
///
@property NSXPCListener *listenerObject;

///
/// The current connection object (used on client-side only).
///
@property NSXPCConnection *currentConnection;

///
/// The remote interface to use while the connection hasn't been validated.
///
@property NSXPCInterface *validatorInterface;


@property NSMutableArray *pendingConnections;
@property NSMutableArray *acceptedConnections;

@end

@implementation SNTXPCConnection

#pragma mark Initializers
- (instancetype)initServerWithName:(NSString *)name {
  self = [super init];
  if (self) {
    Protocol *validatorProtocol = @protocol(XPCConnectionValidityRequest);
    _validatorInterface = [NSXPCInterface interfaceWithProtocol:validatorProtocol];
    _listenerObject = [[NSXPCListener alloc] initWithMachServiceName:name];

    if (!_validatorInterface || !_listenerObject) return nil;

    _pendingConnections = [NSMutableArray array];
    _acceptedConnections = [NSMutableArray array];
  }
  return self;
}

- (instancetype)initClientWithName:(NSString *)name options:(NSXPCConnectionOptions)options {
  self = [super init];
  if (self) {
    Protocol *validatorProtocol = @protocol(XPCConnectionValidityRequest);
    _validatorInterface = [NSXPCInterface interfaceWithProtocol:validatorProtocol];
    _currentConnection = [[NSXPCConnection alloc] initWithMachServiceName:name options:options];

    if (!_validatorInterface || !_currentConnection) return nil;
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
    // A new listener doesn't do anything until a client connects.
    self.listenerObject.delegate = self;
    [self.listenerObject resume];
  } else {
    // A new client begins the validation process.
    NSXPCConnection *connection = self.currentConnection;

    connection.remoteObjectInterface = self.validatorInterface;

    connection.invalidationHandler = ^{
      [self invokeInvalidationHandler];
      self.currentConnection = nil;
    };

    connection.interruptionHandler = ^{ [self.currentConnection invalidate]; };

    [connection resume];

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    [[connection remoteObjectProxy] isConnectionValidWithBlock:^void(BOOL response) {
      pid_t pid = self.currentConnection.processIdentifier;

      MOLCodesignChecker *selfCS = [[MOLCodesignChecker alloc] initWithSelf];
      MOLCodesignChecker *otherCS = [[MOLCodesignChecker alloc] initWithPID:pid];

      if (response && [otherCS signingInformationMatches:selfCS]) {
        [self.currentConnection suspend];
        self.currentConnection.remoteObjectInterface = self.remoteInterface;
        self.currentConnection.exportedInterface = self.exportedInterface;
        self.currentConnection.exportedObject = self.exportedObject;
        [self invokeAcceptedHandler];
        [self.currentConnection resume];
        dispatch_semaphore_signal(sema);
      } else {
        [self invokeRejectedHandler];
        [self.currentConnection invalidate];
        self.currentConnection = nil;
        dispatch_semaphore_signal(sema);
      }
    }];

    // Wait for validation to complete, at most 5s
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
      [self invalidate];
    }
  }
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
  [self.pendingConnections addObject:connection];

  __weak __typeof(connection) weakConnection = connection;

  SNTXPCConnectionValidator *connectionValidator = [[SNTXPCConnectionValidator alloc] init];
  connectionValidator.connection = connection;
  
  connectionValidator.acceptedHandler = ^{
    [self.pendingConnections removeObject:weakConnection];
    [self.acceptedConnections addObject:weakConnection];

    weakConnection.remoteObjectInterface = self.remoteInterface;
    weakConnection.exportedInterface = self.exportedInterface;
    weakConnection.exportedObject = self.exportedObject;
  };
  connectionValidator.rejectedHandler = ^{
    [self.pendingConnections removeObject:weakConnection];
  };

  connection.exportedObject = connectionValidator;
  connection.exportedInterface = self.validatorInterface;

  connection.invalidationHandler = connection.interruptionHandler = ^{
    [self.pendingConnections removeObject:weakConnection];
  };

  [connection resume];

  return YES;
}

- (id)remoteObjectProxy {
  NSXPCConnection *connection;
  if (self.currentConnection.remoteObjectInterface) {
    connection = self.currentConnection;
  } else if ([[self.acceptedConnections firstObject] remoteObjectInterface]) {
    connection = [self.acceptedConnections firstObject];
  }

  return [connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
    [connection invalidate];
  }];
}

- (void)invokeAcceptedHandler {
  if (self.acceptedHandler) {
    self.acceptedHandler();
  }
}

- (void)invokeRejectedHandler {
  if (self.rejectedHandler) {
    self.rejectedHandler();
  }
}

- (void)invokeInvalidationHandler {
  if (self.invalidationHandler) {
    self.invalidationHandler();
  }
}

#pragma mark Connection tear-down

- (void)invalidate {
  if (self.currentConnection) {
    [self.currentConnection invalidate];
    self.currentConnection = nil;
  }
}

@end

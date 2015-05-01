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

#import "SNTCodesignChecker.h"

@protocol XPCConnectionValidityRequest
- (void)isConnectionValidWithBlock:(void (^)(BOOL))block;
@end

@interface SNTXPCConnection ()

///
/// The XPC listener (used on server-side only).
///
@property NSXPCListener *listenerObject;

///
/// The current connection object.
///
@property NSXPCConnection *currentConnection;

///
/// The remote interface to use while the connection hasn't been validated.
///
@property NSXPCInterface *validatorInterface;

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

    __block BOOL verificationComplete = NO;
    [[connection remoteObjectProxy] isConnectionValidWithBlock:^void(BOOL response) {
        pid_t pid = self.currentConnection.processIdentifier;

        SNTCodesignChecker *selfCS = [[SNTCodesignChecker alloc] initWithSelf];
        SNTCodesignChecker *otherCS = [[SNTCodesignChecker alloc] initWithPID:pid];

        if (response && [otherCS signingInformationMatches:selfCS]) {
          [self.currentConnection suspend];
          self.currentConnection.remoteObjectInterface = self.remoteInterface;
          self.currentConnection.exportedInterface = self.exportedInterface;
          self.currentConnection.exportedObject = self.exportedObject;
          [self invokeAcceptedHandler];
          [self.currentConnection resume];
          verificationComplete = YES;
        } else {
          [self invokeRejectedHandler];
          [self.currentConnection invalidate];
          self.currentConnection = nil;
          verificationComplete = YES;
        }
    }];

    // Wait for validation to complete, at most 5s
    for (int sleepLoops = 0; sleepLoops < 1000 && !verificationComplete; sleepLoops++) {
      usleep(5000);
    }
    if (!verificationComplete) [self invalidate];
  }
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
  // Reject connection if a connection already exists. As the invalidation/interruption handlers
  // both cause the currentConnection to be nil'd out, this should be OK.
  if (self.currentConnection) return NO;

  connection.exportedObject = self;
  connection.exportedInterface = self.validatorInterface;

  connection.invalidationHandler = ^{
      [self invokeInvalidationHandler];
      self.currentConnection = nil;
  };

  connection.interruptionHandler = ^{
      // Invalidate the connection, causing the handler above to run
      [self.currentConnection invalidate];
  };

  // At this point the client is connected and can send messages but the only message it can send
  // is isConnectionValidWithBlock: and we won't send anything to it until it has.
  self.currentConnection = connection;

  [connection resume];

  return YES;
}

- (void)isConnectionValidWithBlock:(void (^)(BOOL))block {
  pid_t pid = self.currentConnection.processIdentifier;

  SNTCodesignChecker *selfCS = [[SNTCodesignChecker alloc] initWithSelf];
  SNTCodesignChecker *otherCS = [[SNTCodesignChecker alloc] initWithPID:pid];

  if ([otherCS signingInformationMatches:selfCS]) {
    [self.currentConnection suspend];
    self.currentConnection.remoteObjectInterface = self.remoteInterface;
    self.currentConnection.exportedInterface = self.exportedInterface;
    self.currentConnection.exportedObject = self.exportedObject;
    [self.currentConnection resume];

    [self invokeAcceptedHandler];

    // Let remote end know that we accepted. In acception this must come last otherwise
    // the remote end might start sending messages before the interface is fully set-up.
    block(YES);
  } else {
    // Let remote end know that we rejected. In rejection this must come first otherwise
    // the connection is invalidated before the client ever realizes.
    block(NO);

    [self invokeRejectedHandler];

    [self.currentConnection invalidate];
    self.currentConnection = nil;
  }
}

- (id)remoteObjectProxy {
  if (self.currentConnection && self.currentConnection.remoteObjectInterface) {
    return [self.currentConnection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        [self.currentConnection invalidate];
    }];
  }
  return nil;
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

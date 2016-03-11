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

@interface SNTXPCConnection ()
/// The XPC listener (server only).
@property NSXPCListener *listenerObject;
/// Array of accepted connections (server only).
@property NSMutableArray *acceptedConnections;

/// The current connection object (client only).
@property NSXPCConnection *currentConnection;
@end

@implementation SNTXPCConnection

#pragma mark Initializers

- (instancetype)initServerWithListener:(NSXPCListener *)listener {
  self = [super init];
  if (self) {
    _listenerObject = listener;
    if (!_listenerObject) return nil;
    _acceptedConnections = [NSMutableArray array];
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
  }
  return self;
}

- (instancetype)initClientWithName:(NSString *)name privileged:(BOOL)privileged {
  self = [super init];
  if (self) {
    NSXPCConnectionOptions options = (privileged ? NSXPCConnectionPrivileged : 0);
    _currentConnection = [[NSXPCConnection alloc] initWithMachServiceName:name options:options];
    if (!_currentConnection) return nil;
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
    self.currentConnection.remoteObjectInterface = self.remoteInterface;
    self.currentConnection.interruptionHandler = self.invalidationHandler;
    self.currentConnection.invalidationHandler = self.invalidationHandler;
    [self.currentConnection resume];
  }
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
  pid_t pid = connection.processIdentifier;
  MOLCodesignChecker *otherCS = [[MOLCodesignChecker alloc] initWithPID:pid];
  if (![otherCS signingInformationMatches:[[MOLCodesignChecker alloc] initWithSelf]]) {
    return NO;
  }

  [self.acceptedConnections addObject:connection];

  __weak __typeof(connection) weakConnection = connection;
  connection.interruptionHandler = connection.invalidationHandler = ^{
    [self.acceptedConnections removeObject:weakConnection];
    if (self.invalidationHandler) self.invalidationHandler();
  };

  connection.exportedInterface = self.exportedInterface;
  connection.exportedObject = self.exportedObject;

  [connection resume];
  return YES;
}

- (id)remoteObjectProxy {
  if (self.currentConnection.remoteObjectInterface) {
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
  } else if (self.acceptedConnections.count) {
    for (NSXPCConnection *conn in self.acceptedConnections) {
      [conn invalidate];
    }
    [self.acceptedConnections removeAllObjects];
  }
}

@end

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

#import <MOLXPCConnection/MOLXPCConnection.h>

///  Protocol implemented by the metric service and utilized by santad
///  exporting metrics to a monitoring system.
@protocol SNTMetricServiceXPC

///
///  @param metrics The current metric/counter values serialized to an NSDictionary.
///
- (void)exportForMonitoring:(NSDictionary *)metrics;

@end

@interface SNTXPCMetricServiceInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTMetricServiceXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up
///  before returning.
///
+ (NSXPCInterface *)metricServiceInterface;

///
///  Returns the MachService ID for this service.
///
+ (NSString *)serviceID;

///
///  Retrieve a pre-configured MOLXPCConnection for communicating with santametricservice.
///  Connections just needs any handlers set and then can be resumed and used.
///
+ (MOLXPCConnection *)configuredConnection;

@end

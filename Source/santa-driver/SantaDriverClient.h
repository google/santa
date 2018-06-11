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

#ifndef SANTA__SANTA_DRIVER__SANTADRIVERUSERCLIENT_H
#define SANTA__SANTA_DRIVER__SANTADRIVERUSERCLIENT_H

#include <IOKit/IOUserClient.h>
#include <sys/kauth.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include "SNTKernelCommon.h"
#include "SantaDecisionManager.h"
#include "SantaDriver.h"

///
///  This class is instantiated by IOKit when a new client process attempts to
///  connect to the driver. Starting, stopping, handling connections, allocating
///  shared memory and establishing a data queue is handled here.
///
///  Documentation on how the IOUserClient parts of this code work can be found
///  here:
///  https://developer.apple.com/library/mac/samplecode/SimpleUserClient/Listings/User_Client_Info_txt.html
///  https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/WritingDeviceDriver/WritingDeviceDriver.pdf
///
class com_google_SantaDriverClient : public IOUserClient {
  OSDeclareDefaultStructors(com_google_SantaDriverClient);

 public:
  ///  Called as part of IOServiceOpen in clients
  bool initWithTask(task_t owningTask, void *securityID, UInt32 type) override;

  ///  Called after initWithTask as part of IOServiceOpen
  bool start(IOService *provider) override;

  ///  Called when this class is stopping
  void stop(IOService *provider) override;

  ///  Called when a client manually disconnects (via IOServiceClose)
  IOReturn clientClose() override;

  ///  Called when a client dies
  IOReturn clientDied() override;

  ///  Called in clients with IOConnectSetNotificationPort
  IOReturn registerNotificationPort(
      mach_port_t port, UInt32 type, UInt32 refCon) override;

  ///  Called in clients with IOConnectMapMemory
  IOReturn clientMemoryForType(
      UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory) override;

  ///  Called in clients with IOConnectCallScalarMethod etc. Dispatches
  ///  to the requested selector using the SantaDriverMethods enum in
  ///  SNTKernelCommon.
  IOReturn externalMethod(
      UInt32 selector,
      IOExternalMethodArguments *arguments,
      IOExternalMethodDispatch *dispatch,
      OSObject *target, void *reference) override;

  ///
  ///  The userpsace callable methods are below. Each method corresponds
  ///  to an entry in SantaDriverMethods.
  ///

  ///  Called during client connection.
  static IOReturn open(
      OSObject *target, void *reference, IOExternalMethodArguments *arguments);

  ///  The daemon calls this to allow a binary.
  static IOReturn allow_binary(
      OSObject *target, void *reference,IOExternalMethodArguments *arguments);

  ///  The daemon calls this to deny a binary.
  static IOReturn deny_binary(
      OSObject *target, void *reference, IOExternalMethodArguments *arguments);

  ///  The daemon calls this to acknowledge a binary request. This is used for large binaries that
  ///  may take a while to reach a decision.
  static IOReturn acknowledge_binary(
      OSObject *target, void *reference, IOExternalMethodArguments *arguments);

  ///  The daemon calls this to empty the cache.
  static IOReturn clear_cache(
      OSObject *target, void *reference, IOExternalMethodArguments *arguments);

  ///  The daemon calls this to find out how many items are in the cache
  static IOReturn cache_count(
      OSObject *target, void *reference, IOExternalMethodArguments *arguments);

  ///  The daemon calls this to find out the status of a vnode_id in the cache.
  ///  Output will be a santa_action_t.
  static IOReturn check_cache(
      OSObject *target, void *reference, IOExternalMethodArguments *arguments);

  ///  The daemon calls this to find out how many items are in each cache bucket.
  ///  Input and output are both an instance of santa_bucket_count_t.
  static IOReturn cache_bucket_count(
      OSObject *target, void *reference, IOExternalMethodArguments *arguments);

 private:
  com_google_SantaDriver *myProvider;
  SantaDecisionManager *decisionManager;
};

#endif  // SANTA__SANTA_DRIVER__SANTADRIVERUSERCLIENT_H

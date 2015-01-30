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
#include <IOKit/IOSharedDataQueue.h>
#include <IOKit/IOLib.h>
#include <IOKit/IODataQueueShared.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/proc.h>

#include "SantaDecisionManager.h"
#include "SantaDriver.h"
#include "SantaMessage.h"
#include "SNTKernelCommon.h"

// The maximum number of messages can be kept in the IODataQueue at any time.
const int kMaxQueueEvents = 64;

///
///  This class is instantiated by IOKit when a new client process attempts to
///  connect to the driver. Starting, stopping, handling connections, allocating
///  shared memory and establishing a data queue is handled here.
///
///  Documentation on how the IOUserClient parts of this code work can be found
///  here:
///  @link https://developer.apple.com/library/mac/samplecode/SimpleUserClient/Listings/User_Client_Info_txt.html
///
class com_google_SantaDriverClient : public IOUserClient {
  OSDeclareDefaultStructors(com_google_SantaDriverClient);

 private:
  IOSharedDataQueue *fDataQueue;
  IOMemoryDescriptor *fSharedMemory;
  com_google_SantaDriver *fProvider;
  SantaDecisionManager *fSDM;
  IOLock *fSDMLock;

 public:
  bool start(IOService *provider);
  void stop(IOService *provider);
  IOReturn clientClose();
  bool terminate(IOOptionBits options);
  bool initWithTask(task_t owningTask, void *securityID, UInt32 type);

  IOReturn registerNotificationPort(
      mach_port_t port, UInt32 type, UInt32 refCon);

  IOReturn clientMemoryForType(
      UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory);

  IOReturn externalMethod(
      UInt32 selector,
      IOExternalMethodArguments *arguments,
      IOExternalMethodDispatch *dispatch,
      OSObject *target, void *reference);

  IOReturn open();
  static IOReturn static_open(
      com_google_SantaDriverClient *target,
      void *reference,
      IOExternalMethodArguments *arguments);

  IOReturn close();
  static IOReturn static_close(
      com_google_SantaDriverClient *target,
      void *reference,
      IOExternalMethodArguments *arguments);

  /// The daemon calls this to allow a binary.
  IOReturn allow_binary(uint64_t vnode_id);
  static IOReturn static_allow_binary(
      com_google_SantaDriverClient *target,
      void *reference,
      IOExternalMethodArguments *arguments);

  /// The daemon calls this to deny a binary.
  IOReturn deny_binary(uint64_t vnode_id);
  static IOReturn static_deny_binary(
      com_google_SantaDriverClient *target,
      void *reference,
      IOExternalMethodArguments *arguments);

  /// The daemon calls this to empty the cache.
  IOReturn clear_cache();
  static IOReturn static_clear_cache(
      com_google_SantaDriverClient *target,
      void *reference,
      IOExternalMethodArguments *arguments);

  /// The daemon calls this to find out how many items are in the cache
  IOReturn cache_count(uint64_t *output);
  static IOReturn static_cache_count(
      com_google_SantaDriverClient *target,
      void *reference,
      IOExternalMethodArguments *arguments);
};

#endif  // SANTA__SANTA_DRIVER__SANTADRIVERUSERCLIENT_H

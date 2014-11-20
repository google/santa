/// Copyright 2014 Google Inc. All rights reserved.
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

#include "SantaDriverClient.h"

#define super IOUserClient
#define SantaDriverClient com_google_SantaDriverClient

// The defines above can'be used in this function, must use the full names.
OSDefineMetaClassAndStructors(com_google_SantaDriverClient, IOUserClient);

# pragma mark Driver Management

bool SantaDriverClient::initWithTask(
    task_t owningTask, void *securityID, UInt32 type) {
  if (clientHasPrivilege(
      owningTask, kIOClientPrivilegeAdministrator) != KERN_SUCCESS) {
    LOGW("Unprivileged client attempted to connect.");
    return false;
  }

  if (!super::initWithTask(owningTask, securityID, type)) return false;

  return true;
}

bool SantaDriverClient::start(IOService *provider) {
  fProvider = OSDynamicCast(com_google_SantaDriver, provider);

  if (!fProvider) return false;
  if (!super::start(provider)) return false;

  fSDMLock = IOLockAlloc();

  return true;
}

void SantaDriverClient::stop(IOService *provider) {
  super::stop(provider);
}

IOReturn SantaDriverClient::clientClose() {
  close();
  terminate(kIOServiceSynchronous);

  fProvider = NULL;

  return kIOReturnSuccess;
}

bool SantaDriverClient::terminate(IOOptionBits options) {
  // We have to lock before this check in case the client exits and the kext
  // is unloaded very shortly afterwards.
  IOLockLock(fSDMLock);
  if (fSDM) {
    fSDM->StopListener();

    // Ask santad to shutdown
    santa_message_t message;
    message.action = ACTION_REQUEST_SHUTDOWN;
    message.userId = 0;
    message.pid = 0;
    message.vnode_id = 0;
    fSDM->PostToQueue(message);

    LOGI("Client disconnected.");

    fSDM->release();
    fSDM = NULL;
  }
  IOLockUnlock(fSDMLock);

  if (fProvider && fProvider->isOpen(this)) fProvider->close(this);

  return super::terminate(options);
}

IOReturn SantaDriverClient::registerNotificationPort(mach_port_t port,
                                                     UInt32 type,
                                                     UInt32 ref) {
  if ((!fDataQueue) || (port == MACH_PORT_NULL)) return kIOReturnError;

  fDataQueue->setNotificationPort(port);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::clientMemoryForType(UInt32 type,
                                                IOOptionBits *options,
                                                IOMemoryDescriptor **memory) {
  *memory = NULL;
  *options = 0;

  if (type == kIODefaultMemoryType) {
    if (!fSharedMemory) return kIOReturnNoMemory;
    fSharedMemory->retain();  // client will decrement this ref
    *memory = fSharedMemory;

    return fSDM->StartListener();
  }

  return kIOReturnNoMemory;
}

#pragma mark Callable Methods

IOReturn SantaDriverClient::open() {
  if (isInactive()) return kIOReturnNotAttached;

  if (!fProvider->open(this)) {
    LOGW("A second client tried to connect.");
    return kIOReturnExclusiveAccess;
  }

  fDataQueue = IOSharedDataQueue::withCapacity((sizeof(santa_message_t) +
                                                DATA_QUEUE_ENTRY_HEADER_SIZE)
                                                * kMaxQueueEvents);
  if (!fDataQueue) return kIOReturnNoMemory;

  fSharedMemory = fDataQueue->getMemoryDescriptor();
  if (!fSharedMemory) {
    fDataQueue->release();
    fDataQueue = NULL;
    return kIOReturnVMError;
  }

  IOLockLock(fSDMLock);
  fSDM = SantaDecisionManager::WithQueueAndPID(fDataQueue, proc_selfpid());
  IOLockUnlock(fSDMLock);

  LOGI("Client connected, PID: %d.", proc_selfpid());

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::static_open(
    SantaDriverClient *target,
    void *reference,
    IOExternalMethodArguments *arguments) {
  if (!target) return kIOReturnBadArgument;
  return target->open();
}

IOReturn SantaDriverClient::close() {
  if (!fProvider) return kIOReturnNotAttached;
  if (fProvider->isOpen(this)) fProvider->close(this);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::static_close(
    SantaDriverClient *target,
    void *reference,
    IOExternalMethodArguments *arguments) {
  if (!target) return kIOReturnBadArgument;
  return target->close();
}

IOReturn SantaDriverClient::allow_binary(const uint64_t vnode_id) {
  char vnode_id_str[21];
  snprintf(vnode_id_str, sizeof(vnode_id_str), "%llu", vnode_id);
  fSDM->AddToCache(vnode_id_str,
                   ACTION_RESPOND_CHECKBW_ALLOW,
                   fSDM->GetCurrentUptime());

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::static_allow_binary(
    SantaDriverClient *target,
    void *reference,
    IOExternalMethodArguments *arguments) {
  if (!target) return kIOReturnBadArgument;
  return target->allow_binary(
      *(static_cast<const uint64_t *>(arguments->scalarInput)));
}

IOReturn SantaDriverClient::deny_binary(const uint64_t vnode_id) {
  char vnode_id_str[21];
  snprintf(vnode_id_str, sizeof(vnode_id_str), "%llu", vnode_id);
  fSDM->AddToCache(vnode_id_str,
                   ACTION_RESPOND_CHECKBW_DENY,
                   fSDM->GetCurrentUptime());

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::static_deny_binary(
    com_google_SantaDriverClient *target,
    void *reference,
    IOExternalMethodArguments *arguments) {
  if (!target) return kIOReturnBadArgument;
  return target->deny_binary(
      *(static_cast<const uint64_t *>(arguments->scalarInput)));
}

IOReturn SantaDriverClient::clear_cache() {
  fSDM->ClearCache();
  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::static_clear_cache(
    com_google_SantaDriverClient *target,
    void *reference,
    IOExternalMethodArguments *arguments) {
  if (!target) return kIOReturnBadArgument;
  return target->clear_cache();
}

IOReturn SantaDriverClient::cache_count(uint64_t *output) {
  *output = fSDM->CacheCount();
  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::static_cache_count(
    com_google_SantaDriverClient *target,
    void *reference,
    IOExternalMethodArguments *arguments) {
  if (!target) return kIOReturnBadArgument;
  return target->cache_count(&(arguments->scalarOutput[0]));
}

#pragma mark Method Resolution

IOReturn SantaDriverClient::externalMethod(
    UInt32 selector,
    IOExternalMethodArguments *arguments,
    IOExternalMethodDispatch *dispatch,
    OSObject *target,
    void *reference) {
  // Array of methods callable by clients. The order of these must match the
  // order of the items in |SantaDriverMethods| in SNTKernelCommon.h
  IOExternalMethodDispatch sMethods[kSantaUserClientNMethods] = {
    {
      reinterpret_cast<IOExternalMethodAction>(&SantaDriverClient::static_open),
      0,  // input scalar
      0,  // input struct
      0,  // output scalar
      0   // output struct
    },
    {
      reinterpret_cast<IOExternalMethodAction>(
          &SantaDriverClient::static_close),
      0,
      0,
      0,
      0
    },
    {
      reinterpret_cast<IOExternalMethodAction>(
          &SantaDriverClient::static_allow_binary),
      1,
      0,
      0,
      0
    },
    {
      reinterpret_cast<IOExternalMethodAction>(
          &SantaDriverClient::static_deny_binary),
      1,
      0,
      0,
      0
    },
    {
      reinterpret_cast<IOExternalMethodAction>(
          &SantaDriverClient::static_clear_cache),
      0,
      0,
      0,
      0
    },
    {
      reinterpret_cast<IOExternalMethodAction>(
          &SantaDriverClient::static_cache_count),
      0,
      0,
      1,
      0
    }
  };

  if (selector < static_cast<UInt32>(kSantaUserClientNMethods)) {
    dispatch = &(sMethods[selector]);
    if (!target) target = this;
  } else {
    return kIOReturnBadArgument;
  }

  return super::externalMethod(selector,
                               arguments,
                               dispatch,
                               target,
                               reference);
}

#undef super

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

#include "SantaDriverClient.h"

#define super IOUserClient
#define SantaDriverClient com_google_SantaDriverClient

// The defines above can'be used in this function, must use the full names.
OSDefineMetaClassAndStructors(com_google_SantaDriverClient, IOUserClient);

#pragma mark Driver Management

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
  myProvider = OSDynamicCast(com_google_SantaDriver, provider);

  if (!myProvider) return false;
  if (!super::start(provider)) return false;

  decisionManager = myProvider->GetDecisionManager();
  if (!decisionManager) return false;

  return true;
}

void SantaDriverClient::stop(IOService *provider) {
  super::stop(provider);
  myProvider = nullptr;
  decisionManager = nullptr;
}

IOReturn SantaDriverClient::clientClose() {
  decisionManager->DisconnectClient(true);
  return terminate(kIOServiceSynchronous) ? kIOReturnSuccess : kIOReturnError;
}

bool SantaDriverClient::terminate(IOOptionBits options) {
  decisionManager->DisconnectClient();
  LOGI("Client disconnected.");

  if (myProvider && myProvider->isOpen(this)) myProvider->close(this);

  return super::terminate(options);
}

#pragma mark Fetching memory and data queue notifications

IOReturn SantaDriverClient::registerNotificationPort(
    mach_port_t port, UInt32 type, UInt32 ref) {
  if (port == MACH_PORT_NULL) return kIOReturnError;

  switch (type) {
    case QUEUETYPE_DECISION:
      decisionManager->SetDecisionPort(port);
      break;
    case QUEUETYPE_LOG:
      decisionManager->SetLogPort(port);
      break;
    default:
      return kIOReturnBadArgument;
  }

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::clientMemoryForType(
    UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory) {
  switch (type) {
    case QUEUETYPE_DECISION:
      *options = 0;
      *memory = decisionManager->GetDecisionMemoryDescriptor();
      decisionManager->ConnectClient(proc_selfpid());
      break;
    case QUEUETYPE_LOG:
      *options = 0;
      *memory = decisionManager->GetLogMemoryDescriptor();
      break;
    default:
      return kIOReturnBadArgument;
  }

  (*memory)->retain();

  return kIOReturnSuccess;
}

#pragma mark Callable Methods

IOReturn SantaDriverClient::open(
    OSObject *target,
    void *reference,
    IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  if (me->isInactive()) return kIOReturnNotAttached;
  if (!me->myProvider->open(me)) {
    LOGW("A second client tried to connect.");
    return kIOReturnExclusiveAccess;
  }

  LOGI("Client connected.");

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::allow_binary(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  const uint64_t vnode_id = static_cast<const uint64_t>(arguments->scalarInput[0]);
  if (!vnode_id) return kIOReturnInvalid;
  me->decisionManager->AddToCache(vnode_id, ACTION_RESPOND_ALLOW);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::deny_binary(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  const uint64_t vnode_id = static_cast<const uint64_t>(arguments->scalarInput[0]);
  if (!vnode_id) return kIOReturnInvalid;
  me->decisionManager->AddToCache(vnode_id, ACTION_RESPOND_DENY);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::clear_cache(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  const bool non_root_only = static_cast<const bool>(arguments->scalarInput[0]);
  me->decisionManager->ClearCache(non_root_only);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::cache_count(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  arguments->scalarOutput[0] = me->decisionManager->RootCacheCount();
  arguments->scalarOutput[1] = me->decisionManager->NonRootCacheCount();
  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::check_cache(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  const uint64_t input = static_cast<const uint64_t>(arguments->scalarInput[0]);
  arguments->scalarOutput[0] = me->decisionManager->GetFromCache(input);

  return kIOReturnSuccess;
}

#pragma mark Method Resolution

IOReturn SantaDriverClient::externalMethod(
    UInt32 selector,
    IOExternalMethodArguments *arguments,
    IOExternalMethodDispatch *dispatch,
    OSObject *target,
    void *reference) {
  ///  Array of methods callable by clients. The order of these must match the
  ///  order of the items in SantaDriverMethods in SNTKernelCommon.h
  static IOExternalMethodDispatch sMethods[kSantaUserClientNMethods] = {
    // Function ptr, input scalar count, input struct size, output scalar count, output struct size
    { &SantaDriverClient::open, 0, 0, 0, 0 },
    { &SantaDriverClient::allow_binary, 1, 0, 0, 0 },
    { &SantaDriverClient::deny_binary, 1, 0, 0, 0 },
    { &SantaDriverClient::clear_cache, 1, 0, 0, 0 },
    { &SantaDriverClient::cache_count, 0, 0, 2, 0 },
    { &SantaDriverClient::check_cache, 1, 0, 1, 0 }
  };

  if (selector > static_cast<UInt32>(kSantaUserClientNMethods)) {
    return kIOReturnBadArgument;
  }

  dispatch = &(sMethods[selector]);
  if (!target) target = this;
  return super::externalMethod(selector, arguments, dispatch, target, reference);
}

#undef super

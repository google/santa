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

  decisionManager = myProvider->GetDecisionManager();
  if (!decisionManager) return false;
  decisionManager->retain();

  return super::start(provider);
}

void SantaDriverClient::stop(IOService *provider) {
  myProvider = nullptr;
  decisionManager->release();
  decisionManager = nullptr;
  super::stop(provider);
}

IOReturn SantaDriverClient::clientDied() {
  LOGI("Client died.");
  decisionManager->DisconnectClient(true);
  return terminate(0) ? kIOReturnSuccess : kIOReturnError;
}

IOReturn SantaDriverClient::clientClose() {
  LOGI("Client disconnected.");
  decisionManager->DisconnectClient();
  return terminate(0) ? kIOReturnSuccess : kIOReturnError;
}

bool SantaDriverClient::didTerminate(IOService *provider, IOOptionBits options, bool *defer) {
  decisionManager->DisconnectClient(false, 0);
  if (myProvider && myProvider->isOpen(this)) myProvider->close(this);
  return super::didTerminate(provider, options, defer);
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

  if (arguments->structureInputSize != sizeof(santa_vnode_id_t)) return kIOReturnInvalid;
  santa_vnode_id_t *vnode_id = (santa_vnode_id_t *)arguments->structureInput;
  if (vnode_id->fsid == 0 || vnode_id->fileid == 0) return kIOReturnInvalid;
  me->decisionManager->AddToCache(*vnode_id, ACTION_RESPOND_ALLOW);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::allow_compiler(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  if (arguments->structureInputSize != sizeof(santa_vnode_id_t)) return kIOReturnInvalid;
  santa_vnode_id_t *vnode_id = (santa_vnode_id_t *)arguments->structureInput;
  if (vnode_id->fsid == 0 || vnode_id->fileid == 0) return kIOReturnInvalid;
  me->decisionManager->AddToCache(*vnode_id, ACTION_RESPOND_ALLOW_COMPILER);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::deny_binary(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  if (arguments->structureInputSize != sizeof(santa_vnode_id_t)) return kIOReturnInvalid;
  santa_vnode_id_t *vnode_id = (santa_vnode_id_t *)arguments->structureInput;
  if (vnode_id->fsid == 0 || vnode_id->fileid == 0) return kIOReturnInvalid;
  me->decisionManager->AddToCache(*vnode_id, ACTION_RESPOND_DENY);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::acknowledge_binary(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  if (arguments->structureInputSize != sizeof(santa_vnode_id_t)) return kIOReturnInvalid;
  santa_vnode_id_t *vnode_id = (santa_vnode_id_t *)arguments->structureInput;
  if (vnode_id->fsid == 0 || vnode_id->fileid == 0) return kIOReturnInvalid;
  me->decisionManager->AddToCache(*vnode_id, ACTION_RESPOND_ACK);

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

IOReturn SantaDriverClient::remove_cache_entry(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  if (arguments->structureInputSize != sizeof(santa_vnode_id_t)) return kIOReturnInvalid;
  santa_vnode_id_t *vnode_id = (santa_vnode_id_t *)arguments->structureInput;
  if (vnode_id->fsid == 0 || vnode_id->fileid == 0) return kIOReturnInvalid;
  me->decisionManager->RemoveFromCache(*vnode_id);

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

  if (arguments->structureInputSize != sizeof(santa_vnode_id_t)) return kIOReturnInvalid;
  santa_vnode_id_t *vnode_id = (santa_vnode_id_t *)arguments->structureInput;
  if (vnode_id->fsid == 0 || vnode_id->fileid == 0) return kIOReturnInvalid;
  arguments->scalarOutput[0] = me->decisionManager->GetFromCache(*vnode_id);

  return kIOReturnSuccess;
}

IOReturn SantaDriverClient::cache_bucket_count(
    OSObject *target, void *reference, IOExternalMethodArguments *arguments) {
  SantaDriverClient *me = OSDynamicCast(SantaDriverClient, target);
  if (!me) return kIOReturnBadArgument;

  santa_bucket_count_t *counts = reinterpret_cast<santa_bucket_count_t *>(
      arguments->structureOutput);
  const santa_bucket_count_t *input = reinterpret_cast<const santa_bucket_count_t *>(
      arguments->structureInput);

  uint16_t s = sizeof(counts->per_bucket) / sizeof(uint16_t);
  counts->start = input->start;
  me->decisionManager->CacheBucketCount(counts->per_bucket, &s, &(counts->start));

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
    { &SantaDriverClient::allow_binary, 0, sizeof(santa_vnode_id_t), 0, 0 },
    { &SantaDriverClient::allow_compiler, 0, sizeof(santa_vnode_id_t), 0, 0 },
    { &SantaDriverClient::deny_binary, 0, sizeof(santa_vnode_id_t), 0, 0 },
    { &SantaDriverClient::acknowledge_binary, 0, sizeof(santa_vnode_id_t), 0, 0 },
    { &SantaDriverClient::clear_cache, 1, 0, 0, 0 },
    { &SantaDriverClient::remove_cache_entry, 0, sizeof(santa_vnode_id_t), 0, 0 },
    { &SantaDriverClient::cache_count, 0, 0, 2, 0 },
    { &SantaDriverClient::check_cache, 0, sizeof(santa_vnode_id_t), 1, 0 },
    { &SantaDriverClient::cache_bucket_count, 0, sizeof(santa_bucket_count_t),
        0, sizeof(santa_bucket_count_t) },
  };

  if (selector > static_cast<UInt32>(kSantaUserClientNMethods)) {
    return kIOReturnBadArgument;
  }

  dispatch = &(sMethods[selector]);
  if (!target) target = this;
  return super::externalMethod(selector, arguments, dispatch, target, reference);
}

#undef super

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

#include "SantaDriver.h"

#define super IOService
#define SantaDriver com_google_SantaDriver

// The defines above can'be used in this function, we must use the full names.
OSDefineMetaClassAndStructors(com_google_SantaDriver, IOService);

bool SantaDriver::start(IOService *provider) {
  if (!super::start(provider)) return false;

  santaDecisionManager = new SantaDecisionManager;
  if (!santaDecisionManager->init() ||
      santaDecisionManager->StartListener() != kIOReturnSuccess) {
    santaDecisionManager->release();
    santaDecisionManager = nullptr;
    return false;
  }

  registerService();

  LOGI("Loaded, version %s.", OSKextGetCurrentVersionString());

  return true;
}

void SantaDriver::stop(IOService *provider) {
  santaDecisionManager->StopListener();
  santaDecisionManager->release();
  santaDecisionManager = nullptr;

  LOGI("Unloaded.");

  super::stop(provider);
}

SantaDecisionManager *SantaDriver::GetDecisionManager() const {
  return santaDecisionManager;
}

#undef super

#ifdef CMAKE
#include <mach/mach_types.h>

extern "C" {
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(com.google.santa-driver, SANTA_VERSION, _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = 0;
__private_extern__ kmod_stop_func_t *_antimain = 0;
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;
}
#endif

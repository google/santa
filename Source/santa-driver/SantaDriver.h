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

#ifndef SANTA__SANTA_DRIVER__SANTADRIVER_H
#define SANTA__SANTA_DRIVER__SANTADRIVER_H

#include <IOKit/IOService.h>
#include <libkern/OSKextLib.h>

#include "Source/common/SNTLogging.h"
#include "Source/santa-driver/SantaDecisionManager.h"

///
///  The driver class, which provides the start/stop functions and holds
///  the SantaDecisionManager instance which the connected client
///  communicates with.
///
class com_google_SantaDriver : public IOService {
  OSDeclareDefaultStructors(com_google_SantaDriver);

 public:
  ///  Called by the kernel when the kext is loaded
  bool start(IOService *provider) override;

  ///  Called by the kernel when the kext is unloaded
  void stop(IOService *provider) override;

  ///  Returns a pointer to the SantaDecisionManager created in start().
  SantaDecisionManager *GetDecisionManager() const;

 private:
  SantaDecisionManager *santaDecisionManager;
};

#endif  // SANTA__SANTA_DRIVER__SANTADRIVER_H

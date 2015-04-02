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

#ifndef SANTA__SANTA_DRIVER__SANTAMESSAGE_H
#define SANTA__SANTA_DRIVER__SANTAMESSAGE_H

#include <libkern/c++/OSObject.h>

#include "SNTKernelCommon.h"

///
///  An OSObject wrapper around a @c santa_action_t and a time.
///  Only OSObject subclasses can be inserted into an OSDictionary.
///
class SantaMessage : public OSObject {
  OSDeclareDefaultStructors(SantaMessage)

 public:
  // Returns the time the action was last set.
  uint64_t getMicrosecs() const;

  // Returns the set action.
  santa_action_t getAction() const;

  // Sets the acion and receive time.
  void setAction(const santa_action_t action, const uint64_t microsecs);

 private:
  santa_action_t action_;
  uint64_t microsecs_;
};

#endif  // SANTA__SANTA_DRIVER__SANTAMESSAGE_H

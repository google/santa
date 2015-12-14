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

#include "SantaCachedDecision.h"

OSDefineMetaClassAndStructors(SantaCachedDecision, OSObject);

uint64_t SantaCachedDecision::getMicrosecs() const {
  return microsecs_;
}

santa_action_t SantaCachedDecision::getAction() const {
  return action_;
}

void SantaCachedDecision::setAction(
    const santa_action_t action, const uint64_t microsecs) {
  action_ = action;
  microsecs_ = microsecs;
}

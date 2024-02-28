/// Copyright 2022 Google Inc. All rights reserved.
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

#import "Source/santad/SNTDecisionCache.h"

#include <dispatch/dispatch.h>

#import "Source/common/SNTRule.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/SantaVnodeHash.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDatabaseController.h"

@interface SNTDecisionCache ()
// Cache for sha256 -> date of last timestamp reset.
@property NSCache<NSString *, NSDate *> *timestampResetMap;
@end

@implementation SNTDecisionCache {
  SantaCache<SantaVnode, SNTCachedDecision *> _decisionCache;
}

+ (instancetype)sharedCache {
  static SNTDecisionCache *cache;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    cache = [[SNTDecisionCache alloc] init];
  });
  return cache;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _timestampResetMap = [[NSCache alloc] init];
    _timestampResetMap.countLimit = 100;
  }
  return self;
}

- (void)cacheDecision:(SNTCachedDecision *)cd {
  self->_decisionCache.set(cd.vnodeId, cd);
}

- (SNTCachedDecision *)cachedDecisionForFile:(const struct stat &)statInfo {
  return self->_decisionCache.get(SantaVnode::VnodeForFile(statInfo));
}

- (void)forgetCachedDecisionForVnode:(SantaVnode)vnode {
  self->_decisionCache.remove(vnode);
}

// Whenever a cached decision resulting from a transitive allowlist rule is used to allow the
// execution of a binary, we update the timestamp on the transitive rule in the rules database.
// To prevent writing to the database too often, we space out consecutive writes by 3600 seconds.
- (SNTCachedDecision *)resetTimestampForCachedDecision:(const struct stat &)statInfo {
  SNTCachedDecision *cd = [self cachedDecisionForFile:statInfo];
  if (!cd || cd.decision != SNTEventStateAllowTransitive || !cd.sha256) {
    return cd;
  }

  NSDate *lastUpdate = [self.timestampResetMap objectForKey:cd.sha256];
  if (!lastUpdate || -[lastUpdate timeIntervalSinceNow] > 3600) {
    SNTRule *rule = [[SNTRule alloc] initWithIdentifier:cd.sha256
                                                  state:SNTRuleStateAllowTransitive
                                                   type:SNTRuleTypeBinary
                                              customMsg:nil];
    [[SNTDatabaseController ruleTable] resetTimestampForRule:rule];
    [self.timestampResetMap setObject:[NSDate date] forKey:cd.sha256];
  }

  return cd;
}

@end

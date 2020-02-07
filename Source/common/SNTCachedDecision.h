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

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTKernelCommon.h"

@class MOLCertificate;

///
///  Store information about executions from decision making for later logging.
///
@interface SNTCachedDecision : NSObject

@property santa_vnode_id_t vnodeId;
@property SNTEventState decision;
@property NSString *decisionExtra;
@property NSString *sha256;

@property NSString *certSHA256;
@property NSString *certCommonName;
@property NSArray<MOLCertificate *> *certChain;

@property NSString *quarantineURL;

@property NSString *customMsg;
@property BOOL silentBlock;

@end

/// Copyright 2018 Google Inc. All rights reserved.
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

#ifndef SANTA__SANTA_DRIVER__SANTAPREFIXTREE_H
#define SANTA__SANTA_DRIVER__SANTAPREFIXTREE_H

#include <libkern/c++/OSDictionary.h>
#include <libkern/locks.h>

///
///  SantaPrefixNode is wrapper class representing one char in a prefix.
///
///  OSDefineMetaClassAndStructors is picky so this can't be a nested class.
///
class SantaPrefixNode : public OSObject {
  OSDeclareDefaultStructors(SantaPrefixNode);

 public:
  bool init() override;
  void free() override;

  bool isPrefix;
  // TODO(bur): After writing this I noticed OSDictionary has an O(n) runtime.
  //            Switch to an int[256] lookup table and get rid of SantaPrefixNode.
  OSDictionary *children;
};

///
///  SantaPrefixTree is a simple prefix tree implementation.
///  The runtime for lookup is is not quite linear.
///  Adding and checking prefixes are thread safe.
///
class SantaPrefixTree : public OSObject {
  OSDeclareDefaultStructors(SantaPrefixTree);

 public:
  bool init() override;
  void free() override;

  void AddPrefix(const char *);
  bool HasPrefix(const char *);
  // TODO(bur): Add RemoveAll(). This will allow santad to reset / add prefixes while running.

 private:
  SantaPrefixNode *root_;

  // Locking is probably not needed since we only add prefixes at santad startup before
  // it starts listening for file changes. The read / write lock is cheap, so leaving it in place
  // for now.
  lck_grp_t *spt_lock_grp_;
  lck_grp_attr_t *spt_lock_grp_attr_;
  lck_attr_t *spt_lock_attr_;
  lck_rw_t *spt_lock_;
};

#endif /* SANTA__SANTA_DRIVER__SANTAPREFIXTREE_H */

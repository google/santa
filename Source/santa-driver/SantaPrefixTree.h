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

#include <IOKit/IOLib.h>
#include <libkern/c++/OSObject.h>
#include <libkern/locks.h>

///
///  SantaPrefixTree is a simple prefix tree implementation.
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
  ///
  ///  SantaPrefixNode is a wrapper class that represents one byte.
  ///  1 node can represent a whole ASCII character.
  ///  For example a pointer to the 'A' node will be stored at children[0x41].
  ///  It takes 1-4 nodes to represent a UTF8 encoded Unicode character.
  ///
  ///  The path for "/🤘" would look like this:
  ///      children[0x2f] -> children[0xf0] -> children[0x9f] -> children[0xa4] -> children[0x98]
  ///
  ///  The path for "/dev" is:
  ///      children[0x2f] -> children[0x64] -> children[0x65] -> children[0x76]
  ///
  ///  Lookups of children are O(1).
  ///
  ///  Having the nodes represented by a smaller width, such as a nibble (1/2 byte), would
  ///  drastically decrease the memory footprint but would double required dereferences.
  ///
  class SantaPrefixNode {
   public:
    bool isPrefix;
    void *children[256];

    // Free the direct descendants. Cascades down the whole tree.
    ~SantaPrefixNode() {
      for (int i = 0; i < 256; ++i) {
        if (!children[i]) continue;
        delete (SantaPrefixNode *)children[i];
        children[i] = 0;
      }
    }
  };

  SantaPrefixNode *root_;

  // Each node takes up ~2k, max out at ~512k.
  static const uint32_t kMaxNodes = 256;
  uint32_t current_nodes_;

  lck_grp_t *spt_lock_grp_;
  lck_grp_attr_t *spt_lock_grp_attr_;
  lck_attr_t *spt_lock_attr_;
  lck_rw_t *spt_lock_;
};

#endif /* SANTA__SANTA_DRIVER__SANTAPREFIXTREE_H */

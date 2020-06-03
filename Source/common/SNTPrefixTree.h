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

#include <IOKit/IOReturn.h>
#include <sys/param.h>

#ifdef KERNEL
#include <libkern/locks.h>
#else
// Support for unit testing.
#include <mutex>
#include <pthread.h>
#include <stdint.h>
#endif // KERNEL

///
///  SantaPrefixTree is a simple prefix tree implementation.
///  Operations are thread safe.
///
class SNTPrefixTree {
 public:
  // Add a prefix to the tree.
  // Optionally pass node_count to get the number of nodes after the add.
  IOReturn AddPrefix(const char *, uint64_t *node_count = nullptr);

  // Check if the tree has a prefix for string.
  bool HasPrefix(const char *string);

  // Reset the tree.
  void Reset();

  SNTPrefixTree(uint32_t max_nodes = kDefaultMaxNodes);
  ~SNTPrefixTree();

 private:
  ///
  ///  SantaPrefixNode is a wrapper class that represents one byte.
  ///  1 node can represent a whole ASCII character.
  ///  For example a pointer to the 'A' node will be stored at children[0x41].
  ///  It takes 1-4 nodes to represent a UTF-8 encoded Unicode character.
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
  ///  TODO(bur): Potentially convert this into a full on radix tree.
  ///
  class SantaPrefixNode {
   public:
    bool isPrefix;
    SantaPrefixNode *children[256];
  };

  // PruneNode will remove the passed in node from the tree.
  // The passed in node and all subnodes will be deleted.
  // It is the caller's responsibility to reset the pointer to this node (held by the parent).
  // If the tree is in use grab the exclusive lock.
  void PruneNode(SantaPrefixNode *);

  SantaPrefixNode *root_;

  // Each node takes up ~2k, assuming MAXPATHLEN is 1024 max out at ~2MB.
  static const uint32_t kDefaultMaxNodes = MAXPATHLEN;
  uint32_t max_nodes_;
  uint32_t node_count_;

#ifdef KERNEL
  lck_grp_t *spt_lock_grp_;
  lck_grp_attr_t *spt_lock_grp_attr_;
  lck_attr_t *spt_lock_attr_;
  lck_rw_t *spt_lock_;
  lck_mtx_t *spt_add_lock_;
#else // KERNEL
  pthread_rwlock_t spt_lock_;
  std::mutex *spt_add_lock_;
#endif // KERNEL
};

#endif /* SANTA__SANTA_DRIVER__SANTAPREFIXTREE_H */

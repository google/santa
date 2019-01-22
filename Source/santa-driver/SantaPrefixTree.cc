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

#include "Source/santa-driver/SantaPrefixTree.h"

#ifdef KERNEL
#include <libkern/locks.h>

#include "Source/common/SNTLogging.h"
#else
#include <string.h>

#define LOGD(format, ...) // NOP
#define LOGE(format, ...) // NOP

#define lck_grp_attr_alloc_init() nullptr
#define lck_grp_alloc_init(name, attr) nullptr
#define lck_attr_alloc_init() nullptr

#define lck_rw_alloc_init(g, a) new std::shared_mutex
#define lck_mtx_alloc_init(g, a) new std::mutex

#define lck_attr_free(attr) // NOP
#define lck_grp_free(grp) // NOP
#define lck_grp_attr_free(grp_attr) // NOP

#define lck_rw_lock_shared(l) l->lock_shared()
#define lck_rw_unlock_shared(l) l->unlock_shared()
#define lck_rw_lock_exclusive(l) l->lock()
#define lck_rw_unlock_exclusive(l) l->unlock()

#define lck_rw_lock_shared_to_exclusive(l) ({ l->unlock_shared(); false; })
#define lck_rw_lock_exclusive_to_shared(l) l->unlock(); l->lock_shared()

#define lck_mtx_lock(l) l->lock()
#define lck_mtx_unlock(l) l->unlock()
#endif // KERNEL

SantaPrefixTree::SantaPrefixTree(uint32_t max_nodes) {
  root_ = new SantaPrefixNode();
  node_count_ = 0;
  max_nodes_ = max_nodes;

  spt_lock_grp_attr_ = lck_grp_attr_alloc_init();
  spt_lock_grp_ = lck_grp_alloc_init("santa-prefix-tree-lock", spt_lock_grp_attr_);
  spt_lock_attr_ = lck_attr_alloc_init();

  spt_lock_ = lck_rw_alloc_init(spt_lock_grp_, spt_lock_attr_);
  spt_add_lock_ = lck_mtx_alloc_init(spt_lock_grp_, spt_lock_attr_);
}

IOReturn SantaPrefixTree::AddPrefix(const char *prefix, uint64_t *node_count) {
  // Serialize requests to AddPrefix. Otherwise one AddPrefix thread could overwrite whole
  // branches of another. HasPrefix is still free to read the tree, until AddPrefix needs to
  // modify it.
  lck_mtx_lock(spt_add_lock_);

  // Don't allow an empty prefix.
  if (prefix[0] == '\0') return kIOReturnBadArgument;

  LOGD("Trying to add prefix: %s", prefix);

  // Enforce max tree depth.
  size_t len = strnlen(prefix, max_nodes_);

  // Grab a shared lock until a new branch is required.
  lck_rw_lock_shared(spt_lock_);

  SantaPrefixNode *node = root_;
  for (int i = 0; i < len; ++i) {
    // If there is a node in the path that is considered a prefix, stop adding.
    // For our purposes we only care about the shortest path that matches.
    if (node->isPrefix) break;

    // Only process a byte at a time.
    uint8_t value = prefix[i];

    // Create the child if it does not exist.
    if (!node->children[value]) {
      // Upgrade the shared lock.
      // If the upgrade fails, the shared lock is released.
      if (!lck_rw_lock_shared_to_exclusive(spt_lock_)) {
        // Grab a new exclusive lock.
        lck_rw_lock_exclusive(spt_lock_);
      }

      // Is there enough room for the rest of the prefix?
      if ((node_count_ + (len - i)) > max_nodes_) {
        LOGE("Prefix tree is full, can not add: %s", prefix);

        if (node_count) *node_count = node_count_;
        lck_rw_unlock_exclusive(spt_lock_);
        lck_mtx_unlock(spt_add_lock_);
        return kIOReturnNoResources;
      }

      // Create the rest of the prefix.
      while (i < len) {
        value = prefix[i++];

        SantaPrefixNode *new_node = new SantaPrefixNode();
        node->children[value] = new_node;
        ++node_count_;

        node = new_node;
      }

      // This is the end, mark the node as a prefix.
      LOGD("Added prefix: %s", prefix);

      node->isPrefix = true;

      // Downgrade the exclusive lock
      lck_rw_lock_exclusive_to_shared(spt_lock_);
    } else if (i + 1 == len) {
      // If the child does exist and it is the end...
      // Set the new, higher prefix and prune the now dead nodes.

      if (!lck_rw_lock_shared_to_exclusive(spt_lock_)) {
        lck_rw_lock_exclusive(spt_lock_);
      }

      PruneNode(node->children[value]);

      SantaPrefixNode *new_node = new SantaPrefixNode();
      new_node->isPrefix = true;

      node->children[value] = new_node;
      ++node_count_;

      LOGD("Added prefix: %s", prefix);

      lck_rw_lock_exclusive_to_shared(spt_lock_);
    }

    // Get ready for the next iteration.
    node = node->children[value];
  }

  if (node_count) *node_count = node_count_;

  lck_rw_unlock_shared(spt_lock_);
  lck_mtx_unlock(spt_add_lock_);

  return kIOReturnSuccess;
}

bool SantaPrefixTree::HasPrefix(const char *string) {
  lck_rw_lock_shared(spt_lock_);

  auto found = false;

  SantaPrefixNode *node = root_;

  // A well formed tree will always break this loop. Even if string doesn't terminate.
  const char *p = string;
  while (*p) {
    // Only process a byte at a time.
    node = node->children[(uint8_t)*p++];

    // If it doesn't exist in the tree, no match.
    if (!node) break;

    // If it does exist, is it a prefix?
    if (node->isPrefix) {
      found = true;
      break;
    }
  }

  lck_rw_unlock_shared(spt_lock_);

  return found;
}

void SantaPrefixTree::Reset() {
  lck_rw_lock_exclusive(spt_lock_);

  PruneNode(root_);
  root_ = new SantaPrefixNode();
  node_count_ = 0;

  lck_rw_unlock_exclusive(spt_lock_);
}

void SantaPrefixTree::PruneNode(SantaPrefixNode *target) {
  if (!target) return;

  // For deep trees, a recursive approach will generate too many stack frames. Make a "stack"
  // and walk the tree.
  auto stack = new SantaPrefixNode *[node_count_ + 1];
  if (!stack) {
    LOGE("Unable to prune tree!");

    return;
  }
  auto count = 0;

  // Seed the "stack" with a starting node.
  stack[count++] = target;

  // Start at the target node and walk the tree to find and delete all the sub-nodes.
  while (count) {
    auto node = stack[--count];

    for (int i = 0; i < 256; ++i) {
      if (!node->children[i]) continue;
      stack[count++] = node->children[i];
    }

    delete node;
    --node_count_;
  }

  delete[] stack;
}

SantaPrefixTree::~SantaPrefixTree() {
  lck_rw_lock_exclusive(spt_lock_);
  PruneNode(root_);
  root_ = nullptr;
  lck_rw_unlock_exclusive(spt_lock_);

  #ifdef KERNEL
  if (spt_lock_) {
    lck_rw_free(spt_lock_, spt_lock_grp_);
    spt_lock_ = nullptr;
  }

  if (spt_add_lock_) {
    lck_mtx_free(spt_add_lock_, spt_lock_grp_);
    spt_add_lock_ = nullptr;
  }
  #endif

  if (spt_lock_attr_) {
    lck_attr_free(spt_lock_attr_);
    spt_lock_attr_ = nullptr;
  }

  if (spt_lock_grp_) {
    lck_grp_free(spt_lock_grp_);
    spt_lock_grp_ = nullptr;
  }

  if (spt_lock_grp_attr_) {
    lck_grp_attr_free(spt_lock_grp_attr_);
    spt_lock_grp_attr_ = nullptr;
  }
}

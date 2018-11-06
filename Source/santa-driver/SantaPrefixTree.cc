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

#include "SantaPrefixTree.h"

#include "SNTLogging.h"

#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSSet.h>

SantaPrefixTree::SantaPrefixTree() {
  root_ = new SantaPrefixNode();
  ++node_count_;

  spt_lock_grp_attr_ = lck_grp_attr_alloc_init();
  spt_lock_grp_ = lck_grp_alloc_init("santa-prefix-tree-lock", spt_lock_grp_attr_);
  spt_lock_attr_ = lck_attr_alloc_init();
  spt_lock_ = lck_rw_alloc_init(spt_lock_grp_, spt_lock_attr_);
}

IOReturn SantaPrefixTree::AddPrefix(const char *prefix, uint32_t *node_count) {
  LOGD("Trying to add prefix: %s", prefix);

  // len is the number of bytes (not necessarily the number of characters) representing the string.
  size_t len = strlen(prefix);

  // Have we have created a new branch in the tree?
  auto branched = false;

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
      if (!branched && (node_count_ + (len - i)) > kMaxNodes) {
        LOGE("Prefix tree is full, can not add: %s", prefix);
        if (node_count) *node_count = node_count_;
        lck_rw_unlock_exclusive(spt_lock_);
        return kIOReturnNoResources;
      }

      SantaPrefixNode *new_node = new SantaPrefixNode();

      // If this is the end, mark the node as a prefix.
      if (i + 1 == len) {
        LOGD("Added prefix: %s", prefix);
        new_node->isPrefix = true;
      }

      node->children[value] = (void *)new_node;
      ++node_count_;
      branched = true;

      // Downgrade the exclusive lock
      lck_rw_lock_exclusive_to_shared(spt_lock_);
    } else if (i + 1 == len) {
      // If the child does exist and it is the end...
      // Set the new, higher prefix and prune the now dead nodes.

      if (!lck_rw_lock_shared_to_exclusive(spt_lock_)) {
        lck_rw_lock_exclusive(spt_lock_);
      }

      PruneNode((SantaPrefixNode *)node->children[value]);

      SantaPrefixNode *new_node = new SantaPrefixNode();
      new_node->isPrefix = true;

      node->children[value] = (void *)new_node;
      ++node_count_;

      LOGD("Added prefix: %s", prefix);

      lck_rw_lock_exclusive_to_shared(spt_lock_);
    }

    // Get ready for the next iteration.
    node = (SantaPrefixNode *)node->children[value];
  }

  if (node_count) *node_count = node_count_;

  lck_rw_unlock_shared(spt_lock_);

  return kIOReturnSuccess;
}

bool SantaPrefixTree::HasPrefix(const char *string) {
  lck_rw_lock_shared(spt_lock_);

  auto found = false;

  SantaPrefixNode *node = root_;
  size_t len = strlen(string);
  for (int i = 0; i < len; ++i) {
    // Only process a byte at a time.
    uint8_t value = string[i];

    // Get the next char string.
    node = (SantaPrefixNode *)node->children[value];

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

void SantaPrefixTree::Reset(uint32_t *node_count) {
  lck_rw_lock_exclusive(spt_lock_);

  PruneNode(root_);
  root_ = new SantaPrefixNode();
  ++node_count_;

  if (node_count) *node_count = node_count_;
  LOGD("Prefix tree reset");

  lck_rw_unlock_exclusive(spt_lock_);
}

void SantaPrefixTree::PruneNode(SantaPrefixNode *target) {
  if (!target) return;

  // For deep trees a recursive approach will generate too many stack frames.
  auto stack = OSArray::withCapacity(1);
  auto seen = OSSet::withCapacity(1);

  // Seed the "stack" with a starting node.
  auto target_pointer = OSNumber::withNumber((uint64_t)(void *)target, 64);
  stack->setObject(target_pointer);
  target_pointer->release();

  // Start at the target node and walk the tree to find all the sub-nodes.
  while (stack->getCount()) {
    auto pointer = OSDynamicCast(OSNumber, stack->getLastObject());
    if (!pointer) {
      LOGE("Unable complete prune!");
      break;  // Bail walking the tree, but still delete any seen nodes.
    }

    seen->setObject(pointer);
    stack->removeObject(stack->getCount() - 1);

    auto node = (SantaPrefixNode *)pointer->unsigned64BitValue();
    for (int i = 0; i < 256; ++i) {
      if (!node->children[i]) continue;
      auto child_pointer = OSNumber::withNumber((uint64_t)node->children[i], 64);
      stack->setObject(child_pointer);
      child_pointer->release();
    }
  }

  // Delete all the seen nodes.
  seen->iterateObjects(^bool(OSObject *object) {
    auto pointer = OSDynamicCast(OSNumber, object);
    if (!pointer) {
      LOGE("Unable delete node!");
      return false;  // Continue trying to delete the rest of the nodes.
    }
    auto node = (SantaPrefixNode *)pointer->unsigned64BitValue();
    delete node;
    --node_count_;
    return false;
  });

  OSSafeReleaseNULL(stack);
  OSSafeReleaseNULL(seen);
}

SantaPrefixTree::~SantaPrefixTree() {
  // The locking is probably not necessary here, but I am scared to remove it.
  lck_rw_lock_exclusive(spt_lock_);
  LOGD("Prefix node count: %d", node_count_);
  PruneNode(root_);
  LOGD("Post prune prefix node count: %d", node_count_);
  root_ = nullptr;
  lck_rw_unlock_exclusive(spt_lock_);

  if (spt_lock_) {
    lck_rw_free(spt_lock_, spt_lock_grp_);
    spt_lock_ = nullptr;
  }

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

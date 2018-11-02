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

#define super OSObject
OSDefineMetaClassAndStructors(SantaPrefixTree, OSObject);

bool SantaPrefixTree::init() {
  if (!super::init()) return false;
  root_ = new SantaPrefixNode();

  spt_lock_grp_attr_ = lck_grp_attr_alloc_init();
  spt_lock_grp_ = lck_grp_alloc_init("santa-prefix-tree-lock", spt_lock_grp_attr_);
  spt_lock_attr_ = lck_attr_alloc_init();
  spt_lock_ = lck_rw_alloc_init(spt_lock_grp_, spt_lock_attr_);

  return true;
}

void SantaPrefixTree::AddPrefix(const char *prefix) {
  LOGD("Trying to add prefix: %s", prefix);

  lck_rw_lock_exclusive(spt_lock_);

  // len is the number of bytes (not necessarily the number of characters) representing the string.
  size_t len = strlen(prefix);

  if (current_nodes_ + len > kMaxNodes) {
    LOGE("Prefix tree is full, can not add: %s", prefix);
    lck_rw_unlock_exclusive(spt_lock_);
    return;
  }

  SantaPrefixNode *node = root_;
  for (int i = 0; i < len; ++i) {
    // If there is a node in the path that is considered a prefix, stop adding.
    // For our purposes we only care about the shortest path that matches.
    if (node->isPrefix) break;

    // Only process a byte at a time.
    uint8_t value = prefix[i];

    // Create a new node if needed
    if (!node->children[value]) {
      SantaPrefixNode *newNode = new SantaPrefixNode();
      node->children[value] = (void *)newNode;
      ++current_nodes_;
    }

    // Get ready for the next iteration.
    node = (SantaPrefixNode *)node->children[value];

    // If this is the end, mark the node as a prefix.
    if (i + 1 == len) {
      LOGD("Added prefix: %s", prefix);
      node->isPrefix = true;
      break;  // Unnecessary, but clear.
    }
  }

  lck_rw_unlock_exclusive(spt_lock_);
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

void SantaPrefixTree::free() {
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

  delete root_;
  super::free();
}

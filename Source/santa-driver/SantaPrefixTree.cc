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
  root_ = new SantaPrefixNode;
  root_->init();

  spt_lock_grp_attr_ = lck_grp_attr_alloc_init();
  spt_lock_grp_ = lck_grp_alloc_init("santa-prefix-tree-lock", spt_lock_grp_attr_);
  spt_lock_attr_ = lck_attr_alloc_init();
  spt_lock_ = lck_rw_alloc_init(spt_lock_grp_, spt_lock_attr_);

  return true;
}

void SantaPrefixTree::AddPrefix(const char *prefix) {
  LOGD("Trying to add prefix: %s", prefix);

  lck_rw_lock_exclusive(spt_lock_);

  SantaPrefixNode *node = root_;
  size_t len = strlen(prefix);
  for (int i = 0; i < len; ++i) {
    // If there is a node in the path that is considered a prefix, stop adding.
    // For our purposes we only care about the shortest path that matches.
    if (node->isPrefix) break;

    // Create a single char string.
    const char value[2] = {prefix[i], '\0'};

    // Create a new node if needed
    if (!node->children->getObject(value)) {
      SantaPrefixNode *newNode = new SantaPrefixNode;
      newNode->init();
      node->children->setObject(value, newNode);
    }

    // Get ready for the next iteration.
    node = OSDynamicCast(SantaPrefixNode, node->children->getObject(value));

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
    // Create a single char string.
    const char value[2] = {string[i], '\0'};

    // Get the next char string.
    node = OSDynamicCast(SantaPrefixNode, node->children->getObject(value));

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

  root_->release();
  super::free();
}

OSDefineMetaClassAndStructors(SantaPrefixNode, OSObject);

bool SantaPrefixNode::init() {
  if (!super::init()) return false;
  children = OSDictionary::withCapacity(1);
  isPrefix = false;
  return true;
}

void SantaPrefixNode::free() {
  children->OSCollection::iterateObjects(^bool(OSObject *key) {
    // Counter init()
    children->getObject((OSString *)key)->release();
    return false;
  });

  // Counter setObject();
  children->flushCollection();

  // Counter withCapacity()
  children->release();
  super::free();
}

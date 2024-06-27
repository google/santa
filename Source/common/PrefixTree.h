/// Copyright 2022 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__COMMON__PREFIXTREE_H
#define SANTA__COMMON__PREFIXTREE_H

#include <sys/syslimits.h>

#include <optional>

#import "Source/common/SNTLogging.h"
#include "absl/synchronization/mutex.h"

#if SANTA_PREFIX_TREE_DEBUG
#define DEBUG_LOG LOGD
#else
#define DEBUG_LOG(format, ...)  // NOP
#endif

namespace santa::common {

template <typename ValueT>
class PrefixTree {
 private:
  // Forward declaration
  enum class NodeType;
  class TreeNode;

 public:
  PrefixTree(uint32_t max_depth = PATH_MAX)
      : root_(new TreeNode()), max_depth_(max_depth), node_count_(0) {}

  ~PrefixTree() { PruneLocked(root_); }

  bool InsertPrefix(const char *s, ValueT value) {
    absl::MutexLock lock(&lock_);
    return InsertLocked(s, value, NodeType::kPrefix);
  }

  bool InsertLiteral(const char *s, ValueT value) {
    absl::MutexLock lock(&lock_);
    return InsertLocked(s, value, NodeType::kLiteral);
  }

  bool HasPrefix(const char *input) {
    absl::ReaderMutexLock lock(&lock_);
    return HasPrefixLocked(input);
  }

  std::optional<ValueT> LookupLongestMatchingPrefix(const char *input) {
    if (!input) {
      return std::nullopt;
    }

    absl::ReaderMutexLock lock(&lock_);
    return LookupLongestMatchingPrefixLocked(input);
  }

  void Reset() {
    absl::MutexLock lock(&lock_);
    PruneLocked(root_);
    root_ = new TreeNode();
    node_count_ = 0;
  }

  uint32_t NodeCount() {
    absl::ReaderMutexLock lock(&lock_);
    return node_count_;
  }

#if SANTA_PREFIX_TREE_DEBUG
  void Print() {
    char buf[max_depth_ + 1];
    memset(buf, 0, sizeof(buf));

    absl::ReaderMutexLock lock(&lock_);
    PrintLocked(root_, buf, 0);
  }
#endif

 private:
  ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_)
  bool InsertLocked(const char *input, ValueT value, NodeType node_type) {
    const char *p = input;
    TreeNode *node = root_;

    while (*p) {
      uint8_t cur_byte = (uint8_t)*p;

      TreeNode *child_node = node->children_[cur_byte];
      if (!child_node) {
        // Current node doesn't exist...
        // Create the rest of the nodes in the tree for the given string

        // Keep a pointer to where this new branch starts from. If the
        // input length exceeds max_depth, the new branch will need to
        // be pruned.
        TreeNode *branch_start_node = node;
        uint8_t branch_start_byte = (uint8_t)*p;

        do {
          TreeNode *new_node = new TreeNode();
          node->children_[cur_byte] = new_node;
          node = new_node;
          node_count_++;

          // Check current depth...
          if (p - input >= max_depth_) {
            // Attempted to add a string that exceeded max depth
            // Prune tree from start of this new branch
            PruneLocked(branch_start_node->children_[branch_start_byte]);
            branch_start_node->children_[branch_start_byte] = nullptr;

            return false;
          }

          // Disabling clang format due to local/remote version differences.
          // clang-format off
          cur_byte = (uint8_t)*++p;
          // clang-format on
        } while (*p);

        node->node_type_ = node_type;
        node->value_ = value;

        return true;
      } else if (*(p + 1) == '\0') {
        // Current node exists and we're at the end of our input...
        // Note: The current node's data will be overwritten

        // Only increment node count if the previous node type wasn't already a
        // prefix or literal type (in which case it was already counted)
        if (child_node->node_type_ == NodeType::kInner) {
          node_count_++;
        }

        child_node->node_type_ = node_type;
        child_node->value_ = value;
        return true;
      }

      node = child_node;
      p++;
    }

    // Should only get here when input is an empty string
    return false;
  }

  ABSL_SHARED_LOCKS_REQUIRED(lock_)
  bool HasPrefixLocked(const char *input) {
    TreeNode *node = root_;
    const char *p = input;

    while (*p) {
      node = node->children_[(uint8_t)*p++];

      if (!node) {
        break;
      }

      if (node->node_type_ == NodeType::kPrefix ||
          (*p == '\0' && node->node_type_ == NodeType::kLiteral)) {
        return true;
      }
    }

    return false;
  }

  ABSL_SHARED_LOCKS_REQUIRED(lock_)
  std::optional<ValueT> LookupLongestMatchingPrefixLocked(const char *input) {
    TreeNode *node = root_;
    TreeNode *match = nullptr;
    const char *p = input;

    while (*p) {
      node = node->children_[(uint8_t)*p++];

      if (!node) {
        break;
      }

      if (node->node_type_ == NodeType::kPrefix ||
          (*p == '\0' && node->node_type_ == NodeType::kLiteral)) {
        match = node;
      }
    }

    return match ? std::make_optional<ValueT>(match->value_) : std::nullopt;
  }

  ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_)
  void PruneLocked(TreeNode *target) {
    if (!target) {
      return;
    }

    // For deep trees, a recursive approach will generate too many stack frames.
    // Since the depth of the tree is configurable, err on the side of caution
    // and use a "stack" to walk the tree in a non-recursive manner.
    TreeNode **stack = new TreeNode *[node_count_ + 1];
    if (!stack) {
      LOGE(@"Unable to prune tree!");
      return;
    }

    uint32_t count = 0;

    // Seed the "stack" with a starting node.
    stack[count++] = target;

    // Start at the target node and walk the tree to find and delete all the
    // sub-nodes.
    while (count) {
      TreeNode *node = stack[--count];

      for (int i = 0; i < 256; ++i) {
        if (!node->children_[i]) {
          continue;
        }
        stack[count++] = node->children_[i];
      }

      delete node;
      --node_count_;
    }

    delete[] stack;
  }

#if SANTA_PREFIX_TREE_DEBUG
  ABSL_SHARED_LOCKS_REQUIRED(lock_)
  void PrintLocked(TreeNode *node, char *buf, uint32_t depth) {
    for (size_t i = 0; i < 256; i++) {
      TreeNode *cur_node = node->children_[i];
      if (cur_node) {
        buf[depth] = i;
        if (cur_node->node_type_ != NodeType::kInner) {
          printf("\t%s (type: %s)\n", buf,
                 cur_node->node_type_ == NodeType::kPrefix ? "prefix" : "literal");
        }
        PrintLocked(cur_node, buf, depth + 1);
        buf[depth] = '\0';
      }
    }
  }
#endif

  enum class NodeType {
    kInner = 0,
    kPrefix,
    kLiteral,
  };

  ///
  ///  TreeNode is a wrapper class that represents one byte.
  ///  1 node can represent a whole ASCII character.
  ///  For example a pointer to the 'A' node will be stored at children[0x41].
  ///  It takes 1-4 nodes to represent a UTF-8 encoded Unicode character.
  ///
  ///  The path for "/🤘" would look like this:
  ///      children[0x2f] -> children[0xf0] -> children[0x9f] -> children[0xa4]
  ///      -> children[0x98]
  ///
  ///  The path for "/dev" is:
  ///      children[0x2f] -> children[0x64] -> children[0x65] -> children[0x76]
  ///
  ///  Lookups of children are O(1).
  ///
  ///  Having the nodes represented by a smaller width, such as a nibble (1/2
  ///  byte), would drastically decrease the memory footprint but would double
  ///  required dereferences.
  ///
  ///  TODO(bur): Potentially convert this into a full on radix tree.
  ///
  class TreeNode {
   public:
    TreeNode() : children_(), node_type_(NodeType::kInner) {}
    ~TreeNode() = default;
    TreeNode *children_[256];
    PrefixTree::NodeType node_type_;
    ValueT value_;
  };

  TreeNode *root_;
  const uint32_t max_depth_;
  uint32_t node_count_ ABSL_GUARDED_BY(lock_);
  absl::Mutex lock_;
};

}  // namespace santa::common

#endif

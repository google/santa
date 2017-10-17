// Copyright 2017 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

// Concurrent circular queue to manage a shared memory buffer.
//
// Also see queue_common.h for related definitions.
//
// This implementation is intended to run in the kernel, but will build against
// libc for testing purposes. The intended usage is for the queue buffer to
// be mapped into a shared memory region that is READ-ONLY from userland.
//
// The kernel (writer) can support multiple threads reserving, filling and then
// commiting slots on the circular queue. The range of memory where this is
// happening is referred to as the write window. Conversely, the userland is
// allowed to read within a read window, which it obtains and keep up to date
// by repeatedly calling helm_queue_sync. (The actual API to trigger this call
// will be implemented by ioctl.)

#ifndef SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_H
#define SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_H

#include "QueueCommon.h"

#define MAX_SIZE_AS_BLOB(s) ((size_t)s - sizeof(helm_queue_blob_t))

#ifdef __cplusplus
extern "C" {
#endif

// Note: queue lifecycle
//
// The queue here can be allocated either dynamically or statically.
// Statically-allocated queues need to be initialized with 'helm_queue_init',
// and 'helm_queue_make' can be used to dynamically allocate queues with
// whatever the 'malloc' equivalent is on your platform. No matter how a queue
// was allocated, it is always destroyed with helm_queue_destroy, which takes
// care of freeing it as needed.

// Note: shared memory size
//
// The queue data structure implemented here is used to manage a flat buffer of
// memory. It is effectively an allocator for a shared memory pool.
// The queue can accommodate individual allocations ranging in size from very
// small to multiple pages. When chosing the buffer size, it is best to use
// page-aligned buffer sizes, large enough to allow the writer to continue
// producing output for at least a few seconds if the reader should stop or
// restart.

// Circular queue data structure to manage a shared buffer of memory.
typedef struct {
    // The shared memory of the ring buffer. Read-only from userspace.
    uint8_t *buffer;
    
    // If the queue is not initiliazed all attempts to manipulate it will (safely)
    // fail.
    int initialized;
    
    // Set to true by the sync function if it thinks the queue is stuck.
    int stuck;
    
    // Actual buffer size. Use the USABLE_SIZE macro to get size available to
    // writers.
    size_t buffer_size;
    
    // Must be obtained before manipulating the write_window.
    helm_spinlock_t writer_lock;
    
    // This memory is currently being written to.
    helm_queue_window_t write_window;
    
    // Writer must not write above read_window.bottom. Reader must not read above
    // read_window.top.
    helm_queue_window_t read_window;
    
    // The number of times reserve_slot has been called since last sync.
    uint32_t new_reservations;
    
    // The number of times reserve_slot failed synce last sync.
    uint32_t new_drops;
    
    // The original buffer we got from helm_xalloc. We have to keep this to pass
    // it to helm_xfree. If the queue was allocated statically then the ptr will
    // be NULL.
    helm_buffer_t self_allocation;
} helm_queue_t;

#ifdef HELM_TEST

// Allocates and initializes a circular queue in one step.
//
// A queue created with helm_queue_make should be freed with helm_queue_destroy.
//
// Returns NULL on failure.
helm_queue_t *helm_queue_make(size_t buffer_size, void *buffer);

#endif

// Initializes a circular queue backed by 'buffer'.
//
// The caller is responsible for allocating and freeing the buffer.
//
// A queue that has been initialized should be destroyed with
// helm_queue_destroy.
helm_return_t helm_queue_init(helm_queue_t *queue, size_t buffer_size,
                              void *buffer);

// Destroys the queue. If there are any active writers then this will fail.
//
// If the queue was allocated with helm_queue_make then this will also free it.
helm_return_t helm_queue_destroy(helm_queue_t *queue);

// Synchronizes the reader and the writer.
//
// Firstly, the reader passes its copy of the read_window. The writer will set
// queue.read_window.bottom to match the reader's copy. The writer will then set
// the reader's copy of the read_window.top to the last available (committed)
// slot.
//
// Secondly, the writer sets the slot drop count and other members of the state
// struct.
//
// This function will be called from the ioctl API.
//
// Returns HELM_SUCCESS under normal circumstances.
// Returns HELM_FAILURE if the reader attempted to move the read_window back;
// if so the queue should be reset/dropped.
helm_return_t helm_queue_sync(helm_queue_t *queue, helm_queue_state_t *state);

// Allocates a slot with at least 'size' usable bytes on the queue.
//
// This causes the write window to expand at the top.
//
// Caller MUST call helm_queue_commit_slot quickly otherwise the queue will
// eventually block the reader.
//
// Returns 0 on failure and can be retried later, when more space is available.
// Returns a pointer owned by the queue (do not attempt to free).
helm_queue_slot_t *helm_queue_reserve_slot(helm_queue_t *queue, size_t size);

// Closes the write pointer received from helm_queue_reserve_slot. Returns the
// number of slots that were released to the reader by this commit (might be 0).
//
// This causes the write window to shrink from the bottom.
//
// Once committed, the writer MUST NOT do anything with the slot.
int helm_queue_commit_slot(helm_queue_t *queue, helm_queue_slot_t *slot);

// A convenience wrapper around helm_queue_reserve_slot, reserves a blob of data
// related to the 'ticket' and marks it as such.
//
// If 0 is passed for ticket, then this will create a unique ticket.
//
// Must be followed by helm_queue_commit_blob.
helm_queue_blob_t *helm_queue_reserve_blob(helm_queue_t *queue, size_t size,
                                           int64_t ticket);

// Same as helm_queue_commit_slot, but for blobs; a convenience wrapper.
int helm_queue_commit_blob(helm_queue_t *queue, helm_queue_blob_t *blob);

// Returns a unique (within reason) ticket for use with a helm_blob_t (see
// events_common.h). This is an atomic, auto-incrementing ID that starts at 1
// and wraps around to 1 when it would exceed INT64_MAX.
int64_t helm_claim_ticket(void);

#ifndef NDEBUG
size_t helm_queue_dump(helm_queue_t *queue, char *dump, size_t dump_size);
#endif
    
#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_H
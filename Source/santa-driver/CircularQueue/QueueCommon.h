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

// Common magic numbers and structures used by both (read and write) ends of the
// shared memory queue.

#ifndef SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_COMMON_H
#define SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_COMMON_H

#include "QueueTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

// This slot is currently being written to.
#define HELM_QUEUE_SLOT_RESERVED (1 << 0)
// This slot is ready for a reader.
#define HELM_QUEUE_SLOT_COMMITTED (1 << 1)
// This slot is a wrap-around marker. Reader should not process it and instead
// retry from the start of the ring buffer.
#define HELM_QUEUE_SLOT_WRAPAROUND (1 << 2)

// This value for the 'msg' field indicates the data in buffer should be
// interpreted as an event (see events_common.h).
#define HELM_MSG_EVENT 0xDEC0DED
// This value for 'msg' indicates the data in the buffer are an error message.
#define HELM_MSG_ERROR 0xBAFF1ED
// This value for 'msg' indicates the buffer contains a blob (see helm_blob_t).
#define HELM_MSG_BLOB 0xB10B
// This value for 'msg' indicates the slot should be ignored.
#define HELM_MSG_IGNORE 0xDEAF

// A slot on the circular queue.
typedef struct {
    // The usable space allocated (size of .buffer).
    size_t buffer_size;
    // Flags defined above (HELM_QUEUE_SLOT_*).
    uint32_t flags;
    // Slot message - an arbitrary value may be passed here. It may or may not be
    // suplemented by the data in the buffer. If the 4 bytes in msg are sufficient
    // then buffer_size may be 0.
    //
    // Some messages are listed as constants above, but this field can also be
    // used for arbitrary values (e.g. with the ping command).
    int32_t msg;
    uint8_t buffer[];
    // Arbitrary data follow, buffer_size in length.
} helm_queue_slot_t;

// Passed in a slot's buffer, this structure contains arbitrary binary data sent
// asynchronously. It can be used to pass additional data (too large to embed)
// for helm_blot_t, or sent in response to one-off ioctl commands.
typedef struct {
    // Corresponds to the 'ticket' field on a helm_blob_t - this is the blob that
    // was too large for that struct to embed.
    int64_t ticket;
    // Number of bytes in 'data'. Should be slot's buffer_size - sizeof(this).
    uint64_t data_size;
    // Lieutenant Commander Data was a Soong-type android, the first and only such
    // being to ever enter Starfleet.
    uint8_t data[];
} helm_queue_blob_t;

// Total size of a slot on the queue.
static inline size_t helm_queue_slot_size(helm_queue_slot_t *slot) {
    return sizeof(helm_queue_slot_t) + slot->buffer_size;
}

typedef struct {
    // Relative offset (from base) to the first slot.
    size_t bottom;
    // Relative offset (from base) to the end of the last slot.
    // If top < bottom then the window wraps around.
    size_t top;
} helm_queue_window_t;

// Used to exchange synchronization state between the reader and the writer.
typedef struct {
    // The read window copy of the reader. Is updated by the writer to its new
    // span.
    helm_queue_window_t read_window;
    // The number of times a slot reservation was attempted since the last sync.
    uint32_t new_reservations;
    // Number of times reserveration failed due to lack of room, since the last
    // sync.
    uint32_t new_drops;
} helm_queue_state_t;

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__QUEUE_COMMON_H
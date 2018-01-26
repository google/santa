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

#include "Queue.h"
#include "QueuePlatformExpert.h"
#include "QueueAtomic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_COMMIT_COUNT 100000

#define MIN_BUFFER_SIZE (sizeof(helm_queue_slot_t) * 3)

// There are many reasons to limit the size of the ring buffer to something
// reasonable. Chiefly, the maximum contigious range of memory that AMD64 can
// even theoretically support right now is about 128 TB. Secondly, pointers
// from the upper half and lower half of memory cannot be subtracted, which we
// want to do for debugging.
#define MAX_BUFFER_SIZE ((long)(~0UL >> 1))  // LONG_MAX

#define HELM_TICKET_INIT 1
static helm_atomic_t last_ticket = HELM_ATOMIC_LITERAL(HELM_TICKET_INIT);

// The size available to writers is the buffer size less a reserved slot for the
// wrap-around marker.
static inline size_t usable_buffer_size(helm_queue_t *queue) {
    return queue->buffer_size - sizeof(helm_queue_slot_t);
}

// Returns the start of the ring buffer.
static inline helm_queue_slot_t *first_slot(helm_queue_t *queue) {
    return (helm_queue_slot_t *)queue->buffer;
}

// Return the relative offset of 'slot' with respect to the base of the buffer.
static inline size_t reloffset(helm_queue_t *queue, helm_queue_slot_t *slot) {
    HELM_BUG_ON((uint8_t *)slot > queue->buffer + queue->buffer_size,
                "Slot pointer exceeds buffer.");
    HELM_BUG_ON(slot < first_slot(queue), "Slot pointer underflows buffer.");
    
    return (size_t)((uint8_t *)slot - queue->buffer);
}

// Return a pointer to the slot at the relative 'cursor' to the base of the
// buffer.
static inline helm_queue_slot_t *get_slot(helm_queue_t *queue, size_t cursor) {
    HELM_BUG_ON(cursor > usable_buffer_size(queue),
                "Slot cursor exceeds buffer.");
    return (helm_queue_slot_t *)(queue->buffer + cursor);
}

// Returns whether the queue is empty. A queue is considered empty when the
// top of the write window and the bottom of the read window equal each other.
static inline int is_empty(helm_queue_t *queue) {
    return queue->write_window.top == queue->read_window.bottom;
}

// Computes the wrap-around distance between 'start' and 'end' on the queue.
// Both slot pointers MUST be valid. Returns 0 if pointers are equal, otherwise
// the positive distance from start to end, potentially wrapping around the end
// of the buffer.
static inline size_t distance(helm_queue_t *queue, size_t start, size_t end) {
    HELM_BUG_ON(start > usable_buffer_size(queue),
                "Slot cursor exceeds buffer size in distance calculation.");
    HELM_BUG_ON(end > usable_buffer_size(queue),
                "Slot cursor exceeds buffer size in distance calculation.");
    
    if (start == end) {
        return 0;
    }
    
    if (start < end) {
        return end - start;
    }
    
    return usable_buffer_size(queue) - start + end;
}

// Returns the largest available contiguous buffer on the queue that can be
// reserved. Used for debugging.
static inline size_t get_contiguous_room(helm_queue_t *queue) {
    size_t tail =
    distance(queue, queue->write_window.top, usable_buffer_size(queue));
    size_t head = distance(queue, 0, queue->read_window.bottom);
    size_t room =
    distance(queue, queue->write_window.top, queue->read_window.bottom);
    
    if (room <= tail) {
        return room;
    }
    
    if (head > tail) {
        return head;
    }
    
    return tail;
}

// Aligns the size we reserve for each buffer to sizeof(helm_queue_slot_t).
static inline size_t aligned_slot_size(size_t buffer_size) {
    buffer_size += sizeof(helm_queue_slot_t) - 1;
    return buffer_size - (buffer_size % sizeof(helm_queue_slot_t));
}

typedef enum {
    // Success: buffer can be fitted on the queue without wrapping.
    HELM_ADVANCE_ADVANCE,
    // Success: buffer can be fitted on the queue after wrapping. Wrap marker
    // should be inserted.
    HELM_ADVANCE_WRAP,
    // Failure: there is insufficient room for the write window to expand this
    // much. Can be retried.
    HELM_ADVANCE_NO_ROOM,
    // Permanent failure: The requested buffer is too large to EVER fit on this
    // queue. Do not retry.
    HELM_ADVANCE_TOO_LARGE,
} helm_advance_ret_t;

// Returns the next logical slot, wrapping around as necessary.
// Caller MUST ensure that the memory containing the next slot is initialized!
static inline helm_queue_slot_t *next_slot(helm_queue_t *queue,
                                           helm_queue_slot_t *slot,
                                           size_t limit) {
    size_t off_slot = reloffset(queue, slot);
    size_t off_next = off_slot + helm_queue_slot_size(slot);
    
    // Don't pass the limit, which may be below us.
    if ((off_slot <= limit && off_next >= limit)) {
        return NULL;
    }
    
    // At this point it's correct to have a pointer to the memory where the next
    // slot might be.
    helm_queue_slot_t *next = get_slot(queue, off_next);
    
    HELM_BUG_ON(off_next + helm_queue_slot_size(next) > queue->buffer_size,
                "Next slot would exceed the allocated buffer.");
    
    if (next->flags & HELM_QUEUE_SLOT_WRAPAROUND) {
        return first_slot(queue);
    }
    
    return next;
}

// Looks for a way to fit a contiguous buffer of 'reqsize' bytes onto the queue.
// On success, sets 'cursor' to the new value of write_window.top. Caller MUST
// ensure the queue is locked. See helm_advance_ret_t for return values.
static inline helm_advance_ret_t advance_write_cursor(helm_queue_t *queue,
                                                      size_t reqsize,
                                                      size_t *cursor) {
    *cursor = 0;
    
    if (reqsize > usable_buffer_size(queue)) {
        return HELM_ADVANCE_TOO_LARGE;
    }
    
    if ((distance(queue, queue->write_window.top, queue->read_window.bottom) >
         reqsize) ||
        is_empty(queue)) {
        // There is enough room to fit reqsize under the read window without the top
        // of the write window exceeding or touching the bottom of the read window.
        if (queue->write_window.top + reqsize <= usable_buffer_size(queue)) {
            // There is enough room without wrapping.
            *cursor = queue->write_window.top + reqsize;
            return HELM_ADVANCE_ADVANCE;
        }
        
        if (reqsize < queue->read_window.bottom) {
            // There is enough room under the read window at the start of the buffer,
            // so we wrap around.
            *cursor = 0;
            return HELM_ADVANCE_WRAP;
        }
        
        // If we're here then there is enough room on the buffer but it's not in one
        // contiguous chunk. Too bad - we need to wait.
    }
    
    return HELM_ADVANCE_NO_ROOM;
}

#ifdef NDEBUG

#define debug_queue(r, q)
#define debug_slot(r, s, q)

#else

static inline void debug_queue(const char *reason, helm_queue_t *queue) {
    helm_debug(
               "%s: helm_queue_t @ %p {\n"
               "  .buffer=%p,\n"
               "  .buffer_size=0x%lx,\n"
               "  .write_window={\n"
               "     bottom=$base + 0x%lx = %p,\n"
               "     top=$base + 0x%lx = %p,\n"
               "  },\n"
               "  .read_window={\n"
               "     bottom=$base + 0x%lx = %p,\n"
               "     top=$base + 0x%lx = %p,\n"
               "  },\n"
               "}\n",
               reason, queue, queue->buffer, queue->buffer_size,
               queue->write_window.bottom, queue->buffer + queue->write_window.bottom,
               queue->write_window.top, queue->buffer + queue->write_window.top,
               queue->read_window.bottom, queue->buffer + queue->read_window.bottom,
               queue->read_window.top, queue->buffer + queue->read_window.top);
}

static inline void debug_slot(const char *reason, helm_queue_slot_t *slot,
                              helm_queue_t *queue) {
    if (!slot) {
        helm_debug("%s (NULL)\n", reason);
        return;
    }
    
    helm_debug(
               "%s (@%p=$base + 0x%lx): {\n"
               "  .buffer_size=0x%lx,\n"
               "      (total size: 0x%lx)\n"
               "  .flags=0x%x,\n"
               "  .msg=0x%x,\n"
               "  .queue={\n"
               "    .buffer_size=0x%lx,\n"
               "    .write_window={\n"
               "      bottom=$base + 0x%lx,\n"
               "      top=$base + 0x%lx,\n"
               "    },\n"
               "    .read_window={\n"
               "      bottom=$base + 0x%lx,\n"
               "      top=$base + 0x%lx,\n"
               "    },\n"
               "  }\n"
               "}\n",
               reason, slot, (uint8_t *)slot - queue->buffer, slot->buffer_size,
               sizeof(helm_queue_slot_t) + slot->buffer_size, slot->flags, slot->msg,
               queue->buffer_size, queue->write_window.bottom, queue->write_window.top,
               queue->read_window.bottom, queue->read_window.top);
}

#endif

helm_return_t helm_queue_init(helm_queue_t *queue, size_t buffer_size,
                              void *buffer) {
    if (buffer_size < MIN_BUFFER_SIZE) {
        return HELM_FAILURE;
    }
    
    queue->buffer = buffer;
    queue->buffer_size = buffer_size;
    helm_bzero(buffer, buffer_size);
    
    // Initialize the remaining members.
    queue->write_window.top = 0;
    queue->write_window.bottom = 0;
    queue->read_window.top = 0;
    queue->read_window.bottom = 0;
    queue->new_reservations = 0;
    queue->new_drops = 0;
    
    helm_spin_init(&queue->writer_lock);
    
    // From here on out we're fair game.
    queue->stuck = 0;
    queue->initialized = 1;
    
    return HELM_SUCCESS;
}

#ifdef HELM_TEST

helm_queue_t *helm_queue_make(size_t buffer_size, void *buffer) {
    helm_queue_t *queue = NULL;
    helm_buffer_t queue_alloc = helm_xalloc(sizeof(helm_queue_t));
    
    if (!queue_alloc.ptr) {
        return NULL;
    }
    
    queue = (helm_queue_t *)queue_alloc.ptr;
    queue->self_allocation = queue_alloc;
    
    if (helm_queue_init(queue, buffer_size, buffer) != HELM_SUCCESS) {
        helm_queue_destroy(queue);
        return NULL;
    }
    
    return queue;
}

#endif

helm_return_t helm_queue_destroy(helm_queue_t *queue) {
    helm_irql_t irql;
    helm_spin_lock(&queue->writer_lock, &irql);
    
    // Some writers may still be active.
    if (queue->write_window.bottom != queue->write_window.top) {
        helm_spin_unlock(&queue->writer_lock, &irql);
        return HELM_FAILURE;
    }
    
    queue->initialized = 0;
    helm_spin_unlock(&queue->writer_lock, &irql);
    helm_spin_destroy(&queue->writer_lock);
    
    if (queue->self_allocation.ptr) {
        helm_xfree(queue->self_allocation);
    }
    
    return HELM_SUCCESS;
}

helm_queue_slot_t *helm_queue_reserve_slot(helm_queue_t *queue,
                                           size_t reqsize) {
    helm_irql_t irql;
    size_t buffer_size = aligned_slot_size(reqsize);
    size_t actual_size = buffer_size + sizeof(helm_queue_slot_t);
    
    helm_queue_slot_t *ret = NULL;
    
    if (actual_size < reqsize) {
        // Extremely unlikely: overflow.
        return NULL;
    }
    
    helm_spin_lock(&queue->writer_lock, &irql);
    
    if (!queue->initialized) {
        helm_spin_unlock(&queue->writer_lock, &irql);
        return NULL;
    }
    
    queue->new_reservations++;
    
    size_t newcursor;
    switch (advance_write_cursor(queue, actual_size, &newcursor)) {
        case HELM_ADVANCE_WRAP:
            // We need to write a special slot on the queue to mark the offset at
            // which the ring buffer wraps. There is always room for this slot,
            // because we reserved it in helm_queue_make.
            get_slot(queue, queue->write_window.top)->flags =
            HELM_QUEUE_SLOT_WRAPAROUND | HELM_QUEUE_SLOT_COMMITTED;
            get_slot(queue, queue->write_window.top)->buffer_size = 0;
            
            debug_slot("inserted wrap marker",
                       get_slot(queue, queue->write_window.top), queue);
            
            if (queue->write_window.bottom == queue->write_window.top) {
                // The wrap around slot would be at the bottom of the write window, so
                // we need to simulate committing it by moving the bottom of the write
                // window to the base of the buffer.
                queue->write_window.bottom = 0;
            }
            
            queue->write_window.top = newcursor;
            
            // Now retry.
            HELM_BUG_ON(advance_write_cursor(queue, actual_size, &newcursor) !=
                        HELM_ADVANCE_ADVANCE,
                        "advance_write_cursor returned HELM_ADVANCE_WRAP but there "
                        "still wasn't enough room");
            
            ret = get_slot(queue, queue->write_window.top);
            queue->write_window.top = newcursor;
            break;
        case HELM_ADVANCE_TOO_LARGE:
            ret = 0;
            break;
        case HELM_ADVANCE_NO_ROOM:
            ret = 0;
            helm_debug(
                       "Need at least 0x%lx to reserve 0x%lx. Largest contiguous slot "
                       "available is 0x%lx (total room: 0x%lx).",
                       actual_size, reqsize, get_contiguous_room(queue),
                       distance(queue, queue->write_window.top, queue->read_window.bottom));
            debug_queue("no room", queue);
            break;
        case HELM_ADVANCE_ADVANCE:
            ret = get_slot(queue, queue->write_window.top);
            queue->write_window.top = newcursor;
            break;
        default:
            helm_panic("Invalid helm_advance_ret_t value.");
    }
    
    if (ret) {
        helm_bzero(ret, actual_size);
        ret->flags = HELM_QUEUE_SLOT_RESERVED;
        ret->buffer_size = buffer_size;
        debug_slot("helm_queue_reserve_slot", ret, queue);
    } else {
        queue->new_drops++;
    }
    
    helm_spin_unlock(&queue->writer_lock, &irql);
    return ret;
}

int helm_queue_commit_slot(helm_queue_t *queue, helm_queue_slot_t *slot) {
    helm_irql_t irql;
    helm_spin_lock(&queue->writer_lock, &irql);
    
    if (!queue->initialized) {
        helm_spin_unlock(&queue->writer_lock, &irql);
        return 0;
    }
    
    helm_queue_slot_t *start = slot;
    debug_slot("helm_queue_commit_slot (first)", start, queue);
    slot->flags |= HELM_QUEUE_SLOT_COMMITTED;
    int commited_count = 0;
    
    if (slot == get_slot(queue, queue->write_window.bottom)) {
        HELM_BUG_ON(slot == get_slot(queue, queue->write_window.top),
                    "Commit called but write window is already empty.");
        
        while (slot && slot->flags & HELM_QUEUE_SLOT_COMMITTED) {
            helm_queue_slot_t *next = next_slot(queue, slot, queue->write_window.top);
            
            if (next == first_slot(queue)) {
                queue->write_window.bottom = 0;
            } else {
                queue->write_window.bottom =
                reloffset(queue, slot) + helm_queue_slot_size(slot);
            }
            
            ++commited_count;
            
            if (next && slot < start && next >= start) {
                // We've gone around the whole ring buffer, all of which is committed.
                queue->write_window.bottom = queue->read_window.top;
                queue->write_window.top = queue->write_window.bottom;
                break;
            }
            
            slot = next;
            
            HELM_BUG_ON(commited_count > MAX_COMMIT_COUNT,
                        "Infinite (?) spin on commit.");
        }
    }
    
    helm_debug("commit count: %d", commited_count);
    debug_slot("helm_queue_commit_slot (last)",
               get_slot(queue, queue->write_window.bottom), queue);
    helm_spin_unlock(&queue->writer_lock, &irql);
    
    return commited_count;
}

typedef enum {
    HELM_CURSOR_WITHOUT = 1,  // Cursor is strictly outside the range (not equal
    // to either boundary).
    HELM_CURSOR_WITHIN = 1 << 1,        // Cursor is inside the range.
    HELM_CURSOR_WITHIN_STRICT = 1 << 2  // Cursor is strictly inside the range
    // (not equal to either boundary).
} helm_cursor_cmp_t;

static inline helm_cursor_cmp_t cmp_cursor_range(size_t cursor, size_t bottom,
                                                 size_t top) {
    if (bottom == top) {
        // Range is empty.
        return cursor == top ? HELM_CURSOR_WITHIN : HELM_CURSOR_WITHOUT;
    }
    
    helm_return_t ret = HELM_CURSOR_WITHOUT;
    
    if (bottom > top) {
        // Range is wrapped around.
        if (cursor >= bottom || cursor <= top) {
            ret = HELM_CURSOR_WITHIN;
        }
    } else if (cursor >= bottom && cursor <= top) {
        ret = HELM_CURSOR_WITHIN;
    }
    
    if (ret & HELM_CURSOR_WITHIN && cursor != bottom && cursor != top) {
        ret |= HELM_CURSOR_WITHIN_STRICT;
    }
    
    return ret;
}

// Logs some state useful when debugging stuck writers. Must be called with the
// queue lock and cdev mutex both held.
static void log_stuck_queue(helm_queue_t *queue) {
    helm_queue_slot_t *slot;
    // Make sure to only log this once (otherwise we blow up dmesg).
    if (queue->stuck) {
        return;
    }
    queue->stuck = 1;
    
    slot = get_slot(queue, queue->write_window.bottom);
    helm_warn(
              "Queue looks stuck (uncommitted writers): reader %lx-%lx, writer "
              "%lx-%lx. Slot @%lx: flags=%x, size=%lx, msg=%x.",
              queue->read_window.bottom, queue->read_window.top,
              queue->write_window.bottom, queue->write_window.top,
              queue->write_window.bottom, slot->flags, slot->buffer_size, slot->msg);
}

helm_return_t helm_queue_sync(helm_queue_t *queue, helm_queue_state_t *state) {
    helm_queue_window_t *read_window = &state->read_window;
    helm_irql_t irql;
    helm_return_t ret = HELM_FAILURE;
    
    // Do some basic validation to reject obviously bad input before we even
    // acquire the lock.
    if (read_window->bottom > queue->buffer_size ||
        read_window->top > queue->buffer_size) {
        return HELM_FAILURE;
    }
    
    helm_spin_lock(&queue->writer_lock, &irql);
    
    if (!queue->initialized) {
        goto bail;
    }
    
    // We consider the queue stuck if the reader hasn't moved since last sync, the
    // write window has oustanding writers and we've started dropping. If this
    // happens, log a warning (to dmesg).
    if (read_window->bottom == queue->read_window.bottom &&
        read_window->top == queue->read_window.top && queue->new_drops &&
        queue->write_window.bottom != queue->write_window.top) {
        log_stuck_queue(queue);
    }
    
    // If the reader restarted it won't know where the read window is and we need
    // to initialize it to the last known values.
    if (read_window->bottom == 0 && read_window->top == 0) {
        read_window->bottom = queue->read_window.bottom;
        read_window->top = queue->read_window.top;
    }
    
    // Validate the read window - these values are passed from userspace and could
    // be very wrong. If we detect that the reader's state is invalid it could
    // mean the ioctl is getting fuzzed or that the reader is confused. In either
    // scenario the right thing to do is to reject the sync request.
    
    if (cmp_cursor_range(read_window->bottom, queue->write_window.bottom,
                         queue->write_window.top) &
        HELM_CURSOR_WITHIN_STRICT) {
        goto bail;
    }
    
    if (cmp_cursor_range(read_window->top, queue->write_window.bottom,
                         queue->write_window.top) &
        HELM_CURSOR_WITHIN_STRICT) {
        goto bail;
    }
    
    if (queue->read_window.top != read_window->top) {
        // The reader exceeded the read window it was given last time. This isn't
        // allowed.
        goto bail;
    }
    
    if (queue->read_window.top < queue->write_window.bottom &&
        read_window->top > queue->write_window.bottom) {
        // The reader appears to want to skip the write window into potentially
        // invalid memory.
        goto bail;
    }
    
    // This is how far we can now write.
    queue->read_window.bottom = read_window->bottom;
    
    if (is_empty(queue)) {
        // If the queue is empty then reset it to prevent exhaustion by
        // fragmentation.
        debug_queue("queue reset", queue);
        read_window->bottom = 0;
        read_window->top = 0;
        queue->write_window.bottom = 0;
        queue->write_window.top = 0;
    }
    
    // The reader is free to read up to the bottom of the write window.
    read_window->top = queue->write_window.bottom;
    
    // Sychronize the read windows.
    queue->read_window.top = read_window->top;
    queue->read_window.bottom = read_window->bottom;
    
    // Report stats.
    state->new_reservations = queue->new_reservations;
    queue->new_reservations = 0;
    state->new_drops = queue->new_drops;
    queue->new_drops = 0;
    
    ret = HELM_SUCCESS;
    debug_queue("helm_queue_sync", queue);
bail:
    helm_spin_unlock(&queue->writer_lock, &irql);
    
    return ret;
}

int64_t helm_claim_ticket() {
    return helm_atomic_inc_wrap(&last_ticket, HELM_TICKET_INIT);
}

helm_queue_blob_t *helm_queue_reserve_blob(helm_queue_t *queue, size_t size,
                                           int64_t ticket) {
    size_t slot_size = size + sizeof(helm_queue_blob_t);
    helm_queue_slot_t *slot = helm_queue_reserve_slot(queue, slot_size);
    if (!slot) {
        return NULL;
    }
    
    helm_queue_blob_t *blob = (helm_queue_blob_t *)slot->buffer;
    
    slot->msg = HELM_MSG_BLOB;
    
    if (!ticket) {
        ticket = helm_claim_ticket();
    }
    
    blob->ticket = ticket;
    blob->data_size = size;
    
    return blob;
}

static inline helm_queue_slot_t *blob2slot(helm_queue_blob_t *blob) {
    return (helm_queue_slot_t *)((uint64_t)blob - sizeof(helm_queue_blob_t));
}

int helm_queue_commit_blob(helm_queue_t *queue, helm_queue_blob_t *blob) {
    return helm_queue_commit_slot(queue, blob2slot(blob));
}

#ifdef __cplusplus
}  // extern "C"
#endif
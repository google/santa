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

// This file specifies the data that's transferred over the circular queue.

#ifndef SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__EVENTS_COMMON_H
#define SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__EVENTS_COMMON_H

#include "QueueTypes.h"

typedef int32_t helm_time_opts_t;

#define HELM_TIME_NOT_NULL (1 << 0)
// Indicates the timestamp is relative to boottime.
#define HELM_TIME_RELATIVE (1 << 1)

// The size of helm_blob_t should be a multiple of sizeof(helm_slot_t) because
// alignment rules will always round up and we don't want to needlessly waste
// space. Embedding 0x10 bytes should make the total size 0x20, which works.
#define HELM_BLOB_EMBED_LEN 0x10

typedef struct {
    // If ticket != 0, then expect the rest of the blob to arrive later in a
    // helm_queue_blob_t that will reference this ticket.
    int64_t ticket;
    // The total number of strings in this blob. If count == 1 and the string is
    // short enough then it will be inlined in 'data'. If ticket != 0 then 'data'
    // should be ignored and the recipient should expect 'count' helm_queue_blot_t
    // messages with 'ticket' set to this blob's 'ticket' to supply the data out
    // of band.
    uint64_t count;
    // If the string can fit (count == 1 and ticket == 0) then this will contain
    // the blob inline.
    char data[HELM_BLOB_EMBED_LEN];
} helm_blob_t;

typedef struct {
    int64_t seconds;
    int32_t nanoseconds;
    helm_time_opts_t opts;
} helm_time_t;

// Encapsulates information about a syscall that took place, such as the success
// or failure and saved stack frame.
typedef struct {
    // Instruction pointer.
    uint64_t ip;
    // Return code.
    int64_t ret;
} helm_syscall_t;

typedef struct {
    uint64_t socket;  // Arbitrary unique ID, currently a pointer to the socket.
    uint64_t size;
    int32_t address_family;
    int32_t protocol;
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint16_t sport;
    uint16_t dport;
    int16_t socket_type;
    helm_blob_t data;
} helm_packet_info_t;

// The information in this struct uniquely identifies a process on just about
// every platform.
typedef struct {
    // The time this task forked from its parent.
    helm_time_t fork_ts;
    // A cross-platform representation of a PID. May differ from the kernel type.
    int64_t pid;
    // The pointer to the kernel data structure for this task or process. Used to
    // disambiguate.
    uint64_t ptr;
} helm_task_t;

// Represents task credentials. This is heavily geared towards Linux at the
// moment, and will likely be later extended for XNU.
typedef struct {
    // The user ID the task launched with.
    uint64_t uid;
    // The user group ID the task launched with.
    uint64_t gid;
    // The effective user ID, which may be different through setuid.
    uint64_t euid;
    // The effective user group ID, which may be different through setgid.
    uint64_t egid;
    // On Linux, the uid set through audit_setloginuid.
    // See http://man7.org/linux/man-pages/man3/audit_setloginuid.3.html
    uint64_t loginuid;
    // The thread group ID recorded by the task struct.
    int64_t tgid;
    // The PPID of the task that receives SIGCHLD signals for this task.
    int64_t ppid;
    // The PPID of the original parent process as recorded by the kernel.
    int64_t real_ppid;
    // The PPID as reported by the kernel API in the current namespace.
    int64_t ns_real_ppid;
    // The PPID as reported by the kernel API for the task's namespace.
    int64_t tsk_ns_real_ppid;
} helm_task_cred_t;

// A simplified type of a file-like object.
typedef enum {
    HELM_FILE_NULL = 0,
    // The fd is for a pipe.
    HELM_FILE_PIPE = 1,
    // The fd is for a regular file.
    HELM_FILE_REGULAR = 2,
    // The FD is for something strange and exotic.
    HELM_FILE_OTHER = 99,
} helm_file_type_t;

// A simplified file descriptor.
typedef struct {
    helm_file_type_t file_type;
    // Opaque identifier for the file this FD is pointing at. This could be an
    // inode number, a pipe pointer or something else. The user should not read
    // too much into this value, only using it for comparisons with other file_ids
    // of the same file_type.
    uint64_t file_id;
} helm_fd_t;

typedef struct {
    uint32_t mode;
    uint64_t uid;
    uint64_t gid;
} helm_fileinfo_t;

typedef enum {
    HELM_EVENT_BLOB = 1,
    
    HELM_EVENT_TASK = 0x100,
    HELM_EVENT_FORK = 1 | HELM_EVENT_TASK,
    HELM_EVENT_EXECVE = 2 | HELM_EVENT_TASK,
    HELM_EVENT_EXIT = 3 | HELM_EVENT_TASK,
    
    HELM_EVENT_MOD = 0x200,
    HELM_EVENT_FINIT_MODULE = 1 | HELM_EVENT_MOD,
    HELM_EVENT_INIT_MODULE = 2 | HELM_EVENT_MOD,
    HELM_EVENT_DELETE_MODULE = 3 | HELM_EVENT_MOD,
    
    HELM_EVENT_INET = 0x300,
    HELM_EVENT_SOCKET_OP = 1 | HELM_EVENT_INET,
    HELM_EVENT_PACKET = 2 | HELM_EVENT_INET,
} helm_event_action_t;

typedef enum {
  HELM_PROBE_NAME_FORK,
  HELM_PROBE_NAME_EXECVE,
  HELM_PROBE_NAME_EXECVEAT,
  HELM_PROBE_NAME_EXIT,
  HELM_PROBE_NAME_FINIT_MODULE,
  HELM_PROBE_NAME_INIT_MODULE,
  HELM_PROBE_NAME_DELETE_MODULE,
  HELM_PROBE_NAME_SEND,
  HELM_PROBE_NAME_RECV,
  HELM_PROBE_NAME_NETFILTER_IN4,
  HELM_PROBE_NAME_NETFILTER_OUT4,
  HELM_PROBE_NAME_NETFILTER_IN6,
  HELM_PROBE_NAME_NETFILTER_OUT6,
} helm_probe_name_t;

// A common header for all events.
typedef struct {
    // The time this event should be ordered by. Entities may have additional
    // timestamps.
    helm_time_t time;
    // Type of this event.
    helm_event_action_t action;
    // Source of the event (the probe that generated it).
    helm_probe_name_t source;
} helm_event_hdr_t;

typedef struct {
    helm_event_hdr_t hdr;
    helm_task_t parent;
    helm_task_t child;
    // Credentials associated with the child (not the parent).
    helm_task_cred_t cred;
} helm_event_fork_t;

typedef struct {
    helm_event_hdr_t hdr;
    helm_task_t task;
    helm_task_cred_t cred;
    // This blob contains a helm_syscall_t. Unlike other events for syscalls,
    // execve does not have its syscall information sent inline, because the
    // return value is not known at the time this event is first sent.
    helm_blob_t syscall;
    // Path to the image as specified by the caller (may be fake).
    helm_blob_t path;
    // Path to the image obtained from the kernel's inode cache - may or may not
    // be more useful than path.
    helm_blob_t resolved_path;
    // Hash of the exe file at resolved_path.
    helm_blob_t exe_file_hash;
    // Name of the hash algorithm used.
    helm_blob_t hash_algo_name;
    // Working directory of the task. On Linux, this is called pwd by convention.
    // Everyone else calls it cwd. They mean the same thing.
    helm_blob_t cwd;
    helm_blob_t argv;
    helm_blob_t env;
    // The file at descriptor 0.
    helm_fd_t stdin;
    // The file at descriptor 1.
    helm_fd_t stdout;
    // The file at descriptor 2.
    helm_fd_t stderr;
    // A helm_fileinfo_t sent as a blob.
    helm_blob_t fileinfo;
} helm_event_execve_t;

typedef struct {
    helm_event_hdr_t hdr;
    helm_task_t task;
    helm_task_cred_t cred;
    int64_t exit_code;
} helm_event_exit_t;

typedef struct {
    helm_event_hdr_t hdr;
} helm_event_finit_module_t;

// This event represents an operation by a process on a socket. It's generated
// on send, recv, read, write and possibly others. It should be used to update
// socket-process mappings.
typedef struct {
    helm_event_hdr_t hdr;
    helm_syscall_t syscall;
    helm_task_t task;
    uint64_t socket;  // Arbitrary unique ID, currently a pointer to the socket.
} helm_event_socket_op_t;

// This represents a single packet detected without connection to a system call.
// Direction must be inferred from context, most commonly the probe which
// captured it (hdr.source).
typedef struct {
    helm_event_hdr_t hdr;
    helm_packet_info_t packet;
} helm_event_packet_t;

// A kernel module load or unload.
//
// Whether it is a load or an unload can be determined from `.hdr.action`.
typedef struct {
    helm_event_hdr_t hdr;
    
    // Task requesting the load or unload.
    helm_task_t task;
    
    // helm_syscall_t sent later as a blob.
    helm_blob_t syscall;
    
    // File descriptor for the loaded module, within the caller of finit_module.
    helm_fd_t module_fd;
    
    // Command-line options to the module.
    helm_blob_t options;
    
    // Flags for finit_module, eg MODULE_INIT_IGNORE_MODVERSIONS.
    int64_t finit_module_flags;
    
    // Path of the module for loads, either as given by the caller (for
    // init_module) or implied from the fd (for finit_module).
    helm_blob_t path;
    
    // Hash of the module.
    //
    // TODO(mbp): Maybe unify into a common structure, including the
    // hash_algo_name, used for exec and everything else that sends a hash.
    helm_blob_t module_file_hash;
    // Name of the hash algorithm used.
    helm_blob_t hash_algo_name;
    
    // The name of the module as shown in lsmod. This might be entirely different
    // to the filename.
    helm_blob_t module_name;
} helm_event_kmod_op_t;

#endif  // SANTA__SANTA_DRIVER__CIRCULAR_QUEUE__EVENTS_COMMON_H
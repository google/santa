---
title: Binary Authorization
parent: Intro
redirect_from:
  - /introduction/binary-whitelisting-overview
---

# Binary Authorization Overview

## Background

`santad` subscribes to appropriate
[Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
(ES) framework events to authorize new executions in its
[authorizer client](../binaries/santad#event-streams). This framework ensures
that `santad` has the opportunity to allow or deny the execution of a binary
before it any code in that binary is executed.

## Flow of a New Execution

1.  The `santad` ES client subscribes to the `ES_EVENT_TYPE_AUTH_EXEC` to begin
    receiving and authorizing all new executions on the system.
1.  When a binary is executed (e.g., via `execve(2)` or `posix_spawn(2)`), the
    ES framework gathers
    [some information](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t)
    about the execution and holds up the new image until ES either receives a
    response from `santad` or a timeout occurs.
    *   Note: ES supports authorization result caching that `santad` attempts to
        take advantage of when possible. This cache resides within the ES
        subsystem in the kernel. When a result is already available, ES uses
        that result immediately without collecting event information or waiting
        for a new result. This can greatly reduce performance impact.
1.  The `authorizer client`'s callback is called by the ES framework with the
    event information
1.  `santad` first checks if the event from another ES client on the system and,
    if configured to do so, immediately allows the event and stops all further
    processing for this event.
1.  Some final sanity checks on the event are made before continuing to handle
    the event asynchronously on a concurrent dispatch queue.
    *   Note: A second asynchronous dispatch block is also submitted to execute
        immediately before the event's deadline with the configured default
        response. This helps prevent `santad` from missing an ES response
        deadline which would result in the `santad` process being killed.
1.  `santad` then checks its local authorization cache to determine if full
    evaluation is necessary.
    *   If a cached result already exists, the `authorizer client` responds to
        the ES subsystem immediately and no more event processing occurs.
1.  When `santad` has no local cache entry and must perform a full evaluation,
    it first inserts a placeholder value in its auth cache. If a second event
    for the same binary is received while the first is being processed, it will
    wait for the original event to be processed and result placed into the cache
    instead of performing duplicate processing.
1.  Next, `santad` extracts relevant file and code signing information from the
    event. It computes the file's hash as well verifies the binary's code
    signature.
    *   Note: If code signature validation fails, `santad` will not attempt to
        lookup rules for any properties validated by the code signature
        (currently TeamID, SigningID and CDHash). This means only file hash and
        file scope rules apply.
1.  The extracted information is then used to lookup any matching rules and make
    a decision
    *   There are more details on how these decisions are made in the
        [Rules](../concepts/rules.md) and [Scopes](../concepts/scopes.md)
        documents.
1.  The decision is then posted back to the ES subsystem and local caches are
    updated.
1.  If the binary was blocked, the `Santa GUI` will
    [display a message](../binaries/santa-gui.html#blocked-executions) if
    configured to do so.

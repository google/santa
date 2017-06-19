# santa-driver

santa-driver is a macOS [kernel extension](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KEXTConcept/KEXTConceptIntro/introduction.html) (KEXT) that makes use of the [Kernel Authorization](https://developer.apple.com/library/content/technotes/tn2127/_index.html) (Kauth) KPI. This allows santa-driver to listen for events and either deny or defer the decision of those events. The overall architecture of santa-driver is fairly straightforward. It basically acts as an intermediary layer between Kauth and santad, with some caching to lower the overhead of decision making.

##### Kauth

santa-driver utilizes two Kauth scopes `KAUTH_SCOPE_VNODE` and `KAUTH_SCOPE_FILEOP `. It registers itself with the Kauth API by calling `kauth_listen_scope()` for each scope. This function takes three arguments.

* `const char *scope`
* `kauth_scope_callback_t _callback`_
* `void *contex`

It returns a `kauth_listener_t` that is stored for later use, in Santa's case to stop listening.

###### KAUTH_SCOPE_VNODE

For example here is how santa-driver starts listening for `KAUTH_SCOPE_VNODE` events.

```c++
vnode_listener_ = kauth_listen_scope(
    KAUTH_SCOPE_VNODE, vnode_scope_callback, reinterpret_cast<void *>(this));
```

The function `vnode_scope_callback` is then called for every vnode event. There are many types of vnode events, they complete list can be viewed in the kauth.h. Santa is only concerned with regular files that are generating  `KAUTH_VNODE_EXECUTE ` [1] and `KAUTH_VNODE_WRITE_DATA` events. All non-regular files and unnecessary vnode events are filtered out.

Here is how santa-driver stops listening for `KAUTH_SCOPE_VNODE` events

```c++
kauth_unlisten_scope(vnode_listener_);
```

[1] `KAUTH_VNODE_EXECUTE` events that do not have the `KAUTH_VNODE_ACCESS` advisory bit set.

###### KAUTH_SCOPE_FILEOP

Santa also listens for file operations, this is mainly used for logging [1]. 

* `KAUTH_FILEOP_DELETE`, `KAUTH_FILEOP_RENAME`, `KAUTH_FILEOP_EXCHANGE` and `KAUTH_FILEOP_LINK` are logged
* `KAUTH_FILEOP_EXEC` is used to log `exec()`s. Since the `KAUTH_VNODE_EXECUTE` is used to allow or deny an `exec()` the process arguments have not been setup yet. Since `KAUTH_FILEOP_EXEC` is triggered after an `exec()` it is used to log the `exec()`.

[1] `KAUTH_FILEOP_CLOSE` is used to invalidate that file's representation in the cache. If a file has changed it needs to be re-evalauted. This is particularly necessary for files that were added to the cache with an action of allow.

##### Driver Interface

santa-driver implements a [IOUserClient](https://developer.apple.com/documentation/kernel/iouserclient?language=objc) subclass and santad interacts with it through IOKit/IOKitLib.h functions.

TODO(bur, rah) Flesh out the details

##### Cache

To aid in performance santa-driver utilizes a caching system to hold the state of all observed `exec()` events.

###### Key

The key is a `uint64_t`. The top 32 bits hold the filesystem ID. The bottom 32 bits hold the file unique ID. Together we call this the vnode_id.

```c++
uint64_t vnode_id = (((uint64_t)fsid << 32) | fileid);
```

###### Value

The value is a `uint64_t` containing the action necessary, along with the decision timestamp. The action is stored in the top 8 bits. The decision timestamp is stored in the remaining 56 bits.

```c++
santa_action_t action = (santa_action_t)(cache_val >> 56);
uint64_t decision_time = (cache_val & ~(0xFF00000000000000));
```

The possible actions are:

| Actions                 | Expiry Time      | Description                              |
| ----------------------- | ---------------- | ---------------------------------------- |
| `ACTION_REQUEST_BINARY` | None             | Awaiting an allow or deny decision from santad. |
| `ACTION_RESPOND_ALLOW`  | None             | Allow the `exec()`                       |
| `ACTION_RESPOND_DENY`   | 500 milliseconds | Deny the `exec()`, but re-evalaute after 500 milliseconds. If someone is trying to run a banned binary continually every millisecond for example, only 2 evaluation requests to santad for would occur per second. This mitigates a denial of service type attack on santad. |

###### Invalidation

Besides the expiry time for individual entries the entire cache will be cleared if any of the following events takes place.

* Addition of the blacklist rule
* Addition of a blacklist regex scope
* Cache fills up. This defaults to 10000 entries.

To view the current kernel cache count see the "Kernel info" section of `santactl status`:

```sh
⇒  santactl status
>>> Kernel Info
  Kernel cache count        | 305
```


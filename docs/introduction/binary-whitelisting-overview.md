# Binary Whitelisting Overview

#### Background

The decision flow starts in the kernel. The macOS kernel is extensible by way of a kernel extension (KEXT). macOS makes available kernel programming interfaces (KPIs) to be used by a KEXT. Santa utilizes the Kernel Authorization (Kauth) KPI. This is a very powerful and verbose interface that gives Santa the ability to listen in on most vnode and file systems operations and to take actions, directly or indirectly, on the operations being performed. Still, there are some limitations to Kauth which are pointed out in the santa-driver document. For more information on the santa-driver KEXT see the [santa-driver.md](../details/santa-driver.md) document.

#### Flow of an execve()

This is a high level overview of the binary whitelisting / blacklisting decision process. For a more detailed account of each part, see the respective documentation. This flow does not cover the logging component of Santa, see the [logs.md](../details/logs.md) documentation for more info.

###### Kernel Space

0. santa-driver registers itself as a `KAUTH_SCOPE_VNODE` listener. This flow follows how santa-driver handles `KAUTH_VNODE_EXECUTE` events.
1. A santa-driver Kauth callback function is executed by the kernel when a process is trying to `execve()`. In most cases, the `execve()` takes place right after a process calls `fork()` to start a new process. This function is running on a kernel thread representing the new process. Information on where to find the executable is provided. This information is known as the `vnode_id`.
2. santa-driver then checks if its cache has an allow or deny entry for the `vnode_id`. If so it returns that decision to the Kauth KPI. 
   * If Kauth receives a deny, it will stop the `execve()` from taking place. 
   * If Kauth receives an allow, it will defer the decision. If there are other Kauth listeners, they also have a chance deny or defer.
3. If there is no entry for the `vnode_id` in the cache a few actions occur:
   * santa-driver hands off the decision making to santad.
   * A new entry is created in the cache for the `vnode_id` with a special value of `ACTION_REQUEST_BINARY`.  This is used as a placeholder until the decision from santad comes back. If another process tries to `execve()` the same `vnode_id`, santa-driver will have that thread wait for the in-flight decision from santad. All subsequent `execve()`s for the same `vnode_id` will use the decision in the cache as explained in #2, until the cache is invalidated. See the [santa-driver.md](../details/santa-driver.md) document for more details on the cache invalidation.
   * If the executing file is written to while any of the threads are waiting for a response the `ACTION_REQUEST_BINARY` entry is removed, forcing the decision-making process to be restarted.

###### User Space

1. santad is listening for decision requests from santa-driver.
   * More information is collected about the executable that lives at the `vnode_id`. Since this codepath has a sleeping kernel thread waiting for a decision, extra care is taken to be as performant as possible.
2. santad uses the information it has gathered to make a decision to allow or deny the `execve()`. There are more details on how these decisions are made in the [rules.md](../details/rules.md) and [scopes.md](../details/scopes.md) documents.
3. The decision is posted back to santa-driver.
4. If there was a deny decision, a message is sent to Santa GUI to display a user popup notification.



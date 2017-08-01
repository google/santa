# Binary Whitelisting Overview

#### Background

The decision flow starts in the kernel. The macOS kernel is extendable by way of a kernel extension (KEXT). macOS makes available kernel programming interfaces (KPIs) to be used by a KEXT. Santa makes use of the Kernel Authorization (Kauth) KPI. This is a very powerful and verbose interface that gives Santa the ability to listen in on most vnode and file systems operations and take actions, directly or indirectly, on the operations being performed. Still, there are some limitations to Kauth which are pointed out in the santa-driver document. For more information on the santa-driver KEXT see the santa-driver document.

#### Flow of an exec()

This is a high level overview of the binary whitelisting/blacklisting decision process end to end. For a more a more detailed account of each part, see the respective documents. This flow does not cover the logging component to Santa, see the log document for this information.

###### Kernel Space

0. santa-driver registers itself as a `KAUTH_SCOPE_VNODE` listener. This flow follows how santa-driver handles `KAUTH_VNODE_EXECUTE` events.

1. A santa-driver Kauth callback function is executed by the kernel when a process is trying to `exec()`. In most cases the `exec()` takes place right after a process calls `fork()` to start a new process. This function is running on a kernel thread representing the new process. Information on where to find the executable is provided. The rest of the document this will refer to this information as the the `vnode_id`.
2. santa-driver then checks if its cache has an allow or deny entry for the `vnode_id`. If so it returns that decision to the Kauth KPI. 
   * If Kauth receives a deny, it will stop the `exec()` from taking place. 
   * If Kauth receives an allow, it actually just defers the decision. If there are other Kauth listeners, they also have a chance deny or defer.
3. If there is no entry for the `vnode_id` in the cache a few things take place.
   * At this point santa-driver needs to hand off the decision making to santad.
   * A new entry is created in the cache for the `vnode_id` with a special value of `ACTION_REQUEST_BINARY`.  This is used as a placeholder until the decision from santad comes back. If another process tries to `exec()` the same vnode_id, santa-driver will have that thread wait for the in-flight decision from santad come back. All subsequent `exec()` for the same `vnode_id` will then use the decision in the cache as explained in #2, that is until the cache is invalidated. See the santa-driver document for more details on the cache invalidation.

###### User Space

1. santad is listening for decision requests from santa-driver
   * More information is collected about the executable that lives at the `vnode_id`. Since this codepath has a sleeping kernel thread waiting for a decision, extra care is taken to be as performant as possible.
2. santad uses the information it gathered to make a decision to allow or deny the `exec()`. There are many more details on how these decisions are made in the rules and scopes documents.
3. The decision is posted back to santa-driver.
4. If there was a deny decision, a message is sent to Santa GUI to display a user popup notification.


# santad

The santad process does the heavy lifting when it comes to making decisions
about binary executions. It also handles brokering all of the XPC connections
between the various components of Santa. It does all of this with performance
being at the forefront.

##### A note on performance

On an idling machine, santad and the other components of Santa consume virtually
no CPU and a minimal amount of memory (5-50MB). When lots of processes
`execve()` at the same time, the CPU and memory usage can spike. All of the
`execve()` decisions are made on high priority threads to ensure decisions are
posted back to the kernel as soon as possible. A watchdog thread will log
warnings when sustained high CPU (>20%) and memory (>250MB) usage by santad is
detected.

##### On Launch

The very first thing santad does once it has been launched is to load and
connect to santa-driver. Only one connection may be active at any given time.

At this point, santa-driver is loaded and running in the kernel, but is allowing
all executions and not sending any messages to santad. Before santad tells
santa-driver it is ready to receive messages, it needs to setup a few more
things:

*   The rule and event databases are initialized
*   Connections to Santa (GUI) and santactl sync daemon are established.
*   The config file is processed.

santad is now ready to start processing decision and logging messages from
santa-driver. The listeners are started and santad sits in a run loop awaiting
messages from santa-driver.

##### Running

Messages are read from a shared memory queue (`IODataQueueMemory` ) on a single
thread. A callback is invoked for each message. The callback then dispatches all
the work of processing a decision message to a concurrent high priority queue.
The log messages are dispatched to a low priority queue for processing.

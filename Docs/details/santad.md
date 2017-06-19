# santad

The santad process does the heavy lifting when it comes to making decisions about binary executions. It also handles brokering all of the XPC connections between the various components of Santa. It does all of this with performance being at the forefront. 

##### A note on performance

On an idling machine santad, and really all of the components of Santa, consumes virtually no CPU and a minimal amount of memory (5-50MB). When lots of processes `exec()` at the same time, the CPU and memory usage can spike. All of the `exec()` decisions are made on a high priority threads to ensure decisions are posted back to the kernel as soon as possible. There is a watchdog thread that will log warnings when there is sustained high CPU (>20%) and memory (>250MB) usage by santad.

##### On Launch

The very first thing santad does once it has been launched is to load and connect to santa-driver. Only one connection may be active at any given time.

At this point santa-driver is loaded and running in the kernel but is allowing all executions and not sending any messages to santad. Before santad tells santa-driver it is ready to receive messages it needs to setup a few more things.

The rule and event databases are now initialized. Followed by connection establishment to the Santa (GUI) and santactl sync daemon. The config file is processed and now santad knows what mode it is running in.

Now santad is now ready to start processing decision and logging messages from santa-driver. The listeners are started and santad sits in a run loop awaiting messages from santa-driver. 

##### Running

Messages are read from a shared memory queue (`IODataQueueMemory` ). These messages are read off the queue on a single thread, then a callback is invoked for a each message. The callback then dispatches all the work of processing a decision message to a concurrent high priority queue. The log messages are dispatched to a low priority queue for processing.
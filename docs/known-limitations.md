---
title: Known Limitations
nav_order: 7
---

## Known limitations

- Santa only blocks execution (execve and variants), it doesn't protect against dynamic libraries loaded with dlopen, libraries on disk that have been replaced, or libraries loaded using `DYLD_INSERT_LIBRARIES`.

- Scripts: Santa is currently written to ignore any execution that isn't a binary. After weighing the administration cost versus the benefit, we found it wasn't worthwhile to manage the execution of scripts. Additionally, a number of applications make use of temporary generated scripts and blocking these could cause problems. We're happy to revisit this (or at least make it an option) if it would be useful to others.

- USB Blocking: Santa's USB blocking feature is only meant to stop incidental
  data exfiltration. It is not meant as a hard control. It cannot block:
   * Storage devices mounted during boot prior to Santa having an opportunity to begin authorizing mounts
   * Directly writing to an unmounted, but attached device

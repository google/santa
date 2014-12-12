Santa
=====

Santa is a binary whitelisting/blacklisting system for Mac OS X. It consists of
a kernel extension that monitors for executions, a userland daemon that makes
execution decisions based on the contents of a SQLite database, a GUI agent that
notifies the user in case of a block decision and a command-line utility for
managing the system and synchronizing the database with a server.

Santa is not yet a 1.0. We're writing more tests, fixing bugs, working on TODOs
and finishing up a security audit.

Santa is named because it keeps track of binaries that are naughty and nice.

Santa is a project of Google's Macintosh Operations Team.

Features
========

* Multiple modes: MONITOR and LOCKDOWN. In MONITOR mode all binaries except
those marked as blacklisted will be allowed to run, whilst being logged and
recorded in the database. In LOCKDOWN mode, only whitelisted binaries are
allowed to run.

* Codesign listing: Binaries can be whitelisted/blacklisted by their signing
certificate, so you can trust/block all binaries by a given publisher. The
binary will only be whitelisted by certificate if its signature validates
correctly. However, a decision for a binary will override a decision for a
certificate; i.e. you can whitelist a certificate while blacklisting a binary
signed by that certificate or vice-versa.

* In-kernel caching: whitelisted binaries are cached in the kernel so the
processing required to make a request is only done if the binary
isn't already cached.

* Userland components validate each other: each of the userland components (the
daemon, the GUI agent and the command-line utility) communicate with each other
using XPC and check that their signing certificates are identical before any
communication is accepted.

* Event logging: all executions processed by the userland agent are logged and
all unknown or denied binaries are also stored in the database for upload to a
server.

* Kext uses only KPIs: the kernel extension only uses provided kernel
programming interfaces to do its job. This means that the kext code should
continue to work across OS versions.

Known Issues
============

Santa is not yet a 1.0 and we have some known issues to be aware of:

* Potential race-condition: we currently have a single TODO in the kext code to
investigate a potential race condition where a binary is executed and then very
quickly modified between the kext getting the SHA-1 and the decision being made.

* Kext communication security: the kext will only accept a connection from a
single client at a time and said client must be running as root. We haven't yet
found a good way to ensure the kext only accepts connections from a valid client,
short of hardcoding the SHA-1 in the kext. This shouldn't present a huge problem
as the daemon is loaded on boot-up by launchd, so any later attempts to connect
will be blocked.

* Database protection: the SQLite database is installed with permissions so that
only the root user can read/write it. We're considering approaches to secure
this further.

* Sync client: the command-line client includes a command to synchronize with a
management server, including the uploading of events that have occurred on the
machine and to download new rules. We're still very heavily working on this
server (which is AppEngine-based and will be open-sourced in the future), so the
sync client code is unfinished. It does show the 'API' that we're expecting to
use so if you'd like to write your own management server, feel free to look at
how the client currently works (and suggest changes!)

* Scripts: Santa is currently written to ignore any execution that isn't a
binary. This is because after weighing the administration cost vs the benefit,
we found it wasn't worthwhile. Additionally, a number of applications make use
of temporary generated scripts, which we can't possibly whitelist and not doing
so would cause problems. We're happy to revisit this (or at least make it an
option) if it would be useful to others.

* Documentation: There currently isn't any.

* Tests: There aren't enough of them.

Building
========

```sh
git clone https://github.com/google/santa
cd santa

# Build a debug build. This will install any necessary CocoaPods, create the
# workspace and build, outputting the full log only if an error occurred.
# If CocoaPods is not installed, you'll be prompted to install it.
#
# For other build/install/run options, run rake without any arguments
rake build:debug
```

Note: the Xcode project is setup to use any installed "Mac Developer" certificate
and for security-reasons parts of Santa will not operate properly if not signed.

Kext Signing
============

10.9 requires a special Developer ID certificate to sign kernel extensions and
if the kext is not signed with one of these special certificates a warning will
be shown when loading the kext for the first time. In 10.10 this is a hard error
and the kext will not load at all unless the machine is booted with a debug
boot-arg.

There are two possible solutions for this:

1) Use a pre-built, pre-signed version of the kext that we supply. Each time
changes are made to the kext code we will update the pre-built version that you
can make use of. This doesn't prevent you from making changes to the non-kext
parts of Santa and distributing those. If you make changes to the kext and make
a pull request, we can merge them in and distribute a new version of the
pre-signed kext.

2) Apply for your own [kext signing certificate](https://developer.apple.com/contact/kext/).

Contributing
============

Patches to this project are very much welcome. Please see the [CONTRIBUTING](https://github.com/google/santa/blob/master/CONTRIBUTING.md)
file.

Disclaimer
==========

This is **not** an official Google product.

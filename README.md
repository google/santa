Santa  [![Build Status](https://travis-ci.org/google/santa.png?branch=master)](https://travis-ci.org/google/santa)
=====

<p align="center">
<a href="#santa--">
<img src="./Source/SantaGUI/Resources/Images.xcassets/AppIcon.appiconset/santa-hat-icon-128.png" alt="Santa Icon" />
</a>
</p>

Santa is a binary whitelisting/blacklisting system for macOS. It consists of
a kernel extension that monitors for executions, a userland daemon that makes
execution decisions based on the contents of a SQLite database, a GUI agent that
notifies the user in case of a block decision and a command-line utility for
managing the system and synchronizing the database with a server.

Santa is not yet a 1.0. We're writing more tests, fixing bugs, working on TODOs
and finishing up a security audit.

It is named Santa because it keeps track of binaries that are naughty or nice.

Santa is a project of Google's Macintosh Operations Team.

Admin-Related Features
========

* Multiple modes: In the default MONITOR mode, all binaries except
those marked as blacklisted will be allowed to run, whilst being logged and recorded in the events database. In LOCKDOWN mode, only whitelisted binaries are
allowed to run.

* Event logging: All executions processed by the userland agent are logged.
When in MONITOR and LOCKDOWN modes, all unknown or denied binaries are stored in the database to enable later aggregation.

* Certificate-based rules, with override levels: Instead of relying on a binaries hash (or 'fingerprint'), executables can be whitelisted/blacklisted by their signing
certificate. You can therefore trust/block all binaries by a given publisher that were signed with that cert across version updates. A
binary can only be whitelisted by its certificate if its signature validates
correctly, but a rule for a binaries fingerprint will override a decision for a
certificate; i.e. you can whitelist a certificate while blacklisting a binary
signed with that certificate, or vice-versa.

* Path-based rules (via NSRegularExpression/ICU): This allows a similar feature as Managed Client for OS X's (the precursor to configuration profiles, which used the same implementation mechanism) Application Launch Restrictions via the mcxalr binary. This implementation carries the added benefit of being configurable via regex, and doesn't rely on LaunchServices. As detailed in the wiki, when evaluating rules this holds the lowest precendence.

* Failsafe cert rules: You cannot put in a deny rule that would block the certificate used to sign launchd, a.k.a. pid 1, and therefore all components used in Apple's OS. The binaries in every OS update (and in some cases entire new versions) are therefore auto-whitelisted. This does not affect binaries from Apple's App Store, which use various certs that change regularly for common apps. Likewise, you cannot blacklist Santa itself, and Santa uses a distinct separate cert than other Google apps.

Intentions and Expectations
===========================
No single system or process will stop *all* attacks, or provide 100% security.
Santa is written with the intention of helping protect users from themselves.
People often download malware and trust it, giving the malware credentials, or
allowing unknown software to exfiltrate more data about your system. As a
centrally managed component, Santa can help stop the spread of malware among a
larger fleet of machines. Independently, Santa can aid in analyzing what is
running on your computer.

Santa is part of a defense-in-depth strategy, and you should continue to protect
hosts in whatever other ways you see fit.

Get Help
========

If you have questions or otherwise need help getting started, the
[santa-dev](https://groups.google.com/forum/#!forum/santa-dev) group is a
great place. Please consult the [wiki](https://github.com/google/santa/wiki) and [issues](https://github.com/google/santa/issues) as well.

Security and Performance-Related Features
============
* In-kernel caching: whitelisted binaries are cached in the kernel so the
processing required to make a request is only done if the binary
isn't already cached.

* Userland components validate each other: each of the userland components (the
daemon, the GUI agent and the command-line utility) communicate with each other
using XPC and check that their signing certificates are identical before any
communication is accepted.

* Kext uses only KPIs: the kernel extension only uses provided kernel
programming interfaces to do its job. This means that the kext code should
continue to work across OS versions.

Known Issues
============
Santa is not yet a 1.0 and we have some known issues to be aware of:

* Santa only blocks execution (execve and variants), it doesn't protect against
dynamic libraries loaded with dlopen, libraries on disk that have been replaced, or
libraries loaded using `DYLD_INSERT_LIBRARIES`. As of version 0.9.1 we *did* address [__PAGEZERO missing issues](b87482e) that were exploited in some versions of macOS. We are working on also protecting against similar avenues of attack.

* Kext communication security: the kext will only accept a connection from a
single client at a time and said client must be running as root. We haven't yet
found a good way to ensure the kext only accepts connections from a valid client.

* Database protection: the SQLite database is installed with permissions so that
only the root user can read/write it. We're considering approaches to secure
this further.

* Sync client: The `santactl` command-line client includes a flag to synchronize with a management server, which uploads events that have occurred on the
machine and downloads new rules. We're still very heavily working on this
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

* Documentation: This is currently limited.

* Tests: There aren't enough of them.

Screenshots
===========

A tool like Santa doesn't really lend itself to screenshots, so here's a video instead.

<p align="center">
<img src="https://zippy.gfycat.com/MadFatalAmphiuma.gif" alt="Santa Block Video" />
</p>

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
Kernel extensions on macOS 10.9 and later must be signed using an Apple-provided
Developer ID certificate with a kernel extension flag. Without it, the only way
to load an extension is to enable kext-dev-mode or disable SIP, depending on the
OS version.

There are two possible solutions for this, for distribution purposes:

1) Use a [pre-built, pre-signed version](https://github.com/google/santa/releases)
of the kext that we supply. Each time changes are made to the kext code we will
update the pre-built version that you can make use of. This doesn't prevent you
from making changes to the non-kext parts of Santa and distributing those.
If you make changes to the kext and make a pull request, we can merge them in
and distribute a new version of the pre-signed kext.

2) Apply for your own [kext signing certificate](https://developer.apple.com/contact/kext/).
Apple will only grant this for broad distribution within an organization, they
won't issue them just for testing purposes.

Contributing
============
Patches to this project are very much welcome. Please see the [CONTRIBUTING](https://github.com/google/santa/blob/master/CONTRIBUTING.md)
file.

Disclaimer
==========
This is **not** an official Google product.

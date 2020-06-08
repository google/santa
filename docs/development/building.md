# Building

Santa uses [Bazel](https://bazel.build) for building, testing and releases. The
`master` branch on GitHub is the source-of-truth with features developed in
personal forks.

#### Cloning

Clone the source and change into the directory.

```sh
git clone https://github.com/google/santa
cd santa
```

The above command will default to using the `master` branch. All releases are
built from tagged commits, so if you wanted to build, run or test a specific
release you can checkout that tag:

```sh
git checkout 0.9.33
```

If you want to list all the tags in reverse order:

```sh
git tag --sort=-creatordate
```

#### Building

Build a debug version of Santa:

```sh
bazel build //Source/santa_driver
```

Build a release (optimized) version of Santa:

```sh
bazel build //Source/santa_driver -c opt
```

The output for these commands will be a `santa-driver.zip` file under
`bazel-bin` which, when extracted, will contain all of Santa and should be
installed under `/Library/Extensions`. However, if you're working on Santa and
want a quick way to reload everything, see the next section.

#### Running

When working on Santa, it's useful to have a way to quickly reload all of the
Santa components. For this reason, there's a special rule in the Santa BUILD
file that will compile a new santa-driver, unload Santa if it's running, install
the new Santa in the right place and attempt to load it.

On macOS 10.11+ System Integrity Protection (SIP) prevents loading of kernel
extensions that are not signed by an Apple KEXT signing certificate. To be able
to load and test a non-release version of Santa, SIP will have to be configured
to allow non-Apple KEXT signing certificates.

__This is only to be done a machine that is actively developing, unloading and
loading kernel extensions.__

1.  Boot into Recovery Mode: Reboot and hold down `command+r`
2.  From the utilities menu select `Terminal`
3.  Disable the KEXT feature of SIP: `csrutil enable --without kext`
4.  Reboot

You should now be able to load and run a non-release version of Santa.

Build and run a debug version of Santa.

```sh
bazel run :reload
```

Build and run a release version of Santa.

```sh
bazel run :reload -c opt
```

#### Using Xcode

While Bazel is a very convenient and powerful build system, it can still be
useful to use Xcode for actually working on the code. If you'd like to use Xcode
you can use [Tulsi](https://tulsi.bazel.build) to generate an `.xcodeproj` from
the BUILD file which will use Bazel for actually doing the builds.

#### Debugging

Xcode and lldb can be used to debug Santa, similarly to any other project, with
some exceptions. Instead of clicking the play button to launch and attach to a
process, you can attach to an already running, or soon to by running, component
of Santa. To do this select the Debug menu and choose `Attach to Process by PID
or Name…`. Below are the four components of Santa and who to debug the process
as.

Note: santa-driver (the kernel extension) cannot be debugged by attaching with
Xcode.

Note: Xcode can attach to santad without interruption, however any breakpoints
in the decision making codepath can deadlock the machine. Using lldb directly to
attach to santad will deadlock the machine.

process  | user
-------- | ----
santad   | root
Santa*   | me
santactl | me
santabs  | root

Xcode will then wait for the process to start. Issue this command to restart all
the Santa processes in debug mode.

*The Santa (GUI) process is the only component of Santa that can be launched and
debugged from Xcode directly. All the other components are launched with
privileges and/or are scoped to an XPC service that launchd scopes to a hosting
bundle. Thus the need for the `Attach to Process by PID or Name…` technique. See
the [ipc](../details/ipc.md) document for for details.

```sh
bazel run :reload
```

Now the process is attached in Xcode and you can debug your day away.

#### Tests

Run all the logic / unit tests

```sh
bazel test :unit_tests
```

Run all of santa-driver kernel extension tests

```sh
bazel run //Source/santa_driver:kernel_tests
```

#### Releases

Creates a release build of Santa with a version based of the newest tag. Also
saves the dsym files for each component of Santa. This makes debugging and
interpreting future crashes or kernel panics much easier.

```sh
bazel build :release
```

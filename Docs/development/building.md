

# Building

Santa makes use of [rake](https://ruby.github.io/rake/) for building and testing Santa. All of the [releases](https://github.com/google/santa/releases) are made using this same process. Santa's releases are codesigned with Google's KEXT signing certificate. This allows Santa to be loaded with SIP fully enabled.

#### Cloning

Clone the source and change into the directory.

```sh
git clone https://github.com/google/santa
cd santa
```

The above command will default to using the `master` branch. If you wanted to build, run or test a specific version of Santa use this command.

```sh
git checkout <version, i.e. 0.9.19>
```

#### Building

Build a debug version of Santa. This keeps all the debug symbols, adds additional logs and does not optimize the compiled output. For speed sensitive tests make sure to benchmark a release version too.

```sh
rake build:debug
```

Build a release version of Santa.

```sh
rake build:release
```

Both of these just output the binaries that makeup Santa in the default Xcode build location. To actually run  what was built, see the next section.

#### Running

On macOS 10.11+ System Integrity Protection (SIP) prevents loading of kernel extensions that are not signed by an Apple KEXT signing certificate. To be able to load and test a non-release version of Santa, SIP will have to be configured to allow non-Apple KEXT signing certificates.

__This is only to be done a machine that is actively developing, unloading and loading kernel extensions.__

1. Boot into Recovery Mode: Reboot and hold down `command+r`
2. From the utilities menu select `Terminal`
3. Disable the KEXT feature of SIP: `csrutil enable --without kext`
4. Reboot

You should now be able to load and run a non-release version of Santa.

Build and run a debug version of Santa.

```sh
rake reload:debug
```

Build and run a release version of Santa.

```sh
rake reload:release
```

#### Debugging

Xcode and lldb can be used to debug Santa, just like any other project. Instead of clicking the play button to launch and attach to a process, you can attach to an already running, or soon to by running, component of Santa. To do this select the Debug menu and choose `Attach to Process by PID or Name… `. Below are the four components of Santa and who to debug the process as. 

Note: santa-driver (the kernel extension) cannot be debugged by attaching with Xcode.

Note: Xcode can attach to santad without interruption, however any breakpoints in the decision making codepath can deadlock the machine. Using lldb directly to attach to santad will deadlock the machine.

| process  | user |
| -------- | ---- |
| santad   | root |
| Santa*   | me   |
| santactl | me   |
| santabs  | root |

Xcode will then wait for the process to start. Issue this command to restart all the Santa processes in debug mode.

*The Santa (GUI) process is the only component of Santa that can be launched and debugged from Xcode directly. All the other components are launched with privileges and/or are scoped to an XPC service that launchd scopes to a hosting bundle. Thus the need for the `Attach to Process by PID or Name…` technique.  See the [ipc](../details/ipc.md) document for for details.

```sh
rake reload:debug
```

Now the process is attached in Xcode and you can debug your day away.

#### Tests

Run all the logic / unit tests

```sh
rake tests:logic
```

Run all of santa-driver kernel extension tests

```sh
rake tests:kernel
```

#### Releases

Creates a release build of Santa with a version based of the newest tag. Also saves the dsym files for each component of Santa. This makes debugging and interpreting future crashes or kernel panics much easier.

```sh
rake dist
```

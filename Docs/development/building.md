

Santa makes use of [rake](https://ruby.github.io/rake/) for building and testing Santa. All of the [releases](https://github.com/google/santa/releases) are made using this same process. Santa's releases are codesigned with Google's kext signing certificate. This allows Santa to be loaded with SIP enabled, as of macOS 10.12. macOS 10.13+ will most likely require user consent, even when signed with Google's kext signing certificate.

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

Build a debug version of Santa. This keeps all the debug symbols, adds additional logs and does not optimize the compiled output. For speed sensitive test make sure to benchmark a release version too.

```sh
rake build:debug
```

Build a release version of Santa.

```sh
rake build:release
```

Both of these just output the binaries that makeup Santa in the default Xcode build location. To actually run  what was build see the next section.

#### Running

On macOS 10.11+ System Integrity Protection (SIP) prevents loading of kernel extensions that are not signed by an Apple generated kext signing certificate. To be able to load and test a non-release version of Santa, SIP will have to configured. That is, of course, unless you have access to a kext signing certificate on your development machine.

__This is only to be done a machine that is actively developing, unloading and loading kernel extensions.__

1. Boot into Recovery Mode: Reboot and hold down `command+r
2. From the utilities menu select `Terminal`
3. Disable the kext feature of SIP: `csrutil enable --without kext`
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

Xcode can be used to debug Santa with lldb, just like any other project. Instead of clicking the play button to attach to a process, you can attach to an already running component of Santa. To do this select the Debug menu and choose `Attach to Process by PID or Name… ` . Below are the four components of Santa and who to debug the process as. Note, santa-driver (the kernel extension) cannot be debugged by attaching with Xcode.

| process  | user |
| -------- | ---- |
| santad   | root |
| Santa    | me   |
| santactl | me   |
| santabs  | root |

Xcode will then wait for the process to start. Issue this command to restart all the Santa processes in debug mode.

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

```sh
rake dist
```
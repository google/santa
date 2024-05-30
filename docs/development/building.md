---
title: Building
parent: Development
---

# Building

<!-- markdown-link-check-disable-next-line -->
Santa uses [Bazel](https://bazel.build) for building, testing and releases. The
`main` branch on GitHub is the source-of-truth with features developed in
personal forks.

#### Cloning

Clone the source and change into the directory.

```sh
git clone https://github.com/google/santa
cd santa
```

The above command will default to using the `main` branch. All releases are
built from tagged commits, so if you wanted to build, run or test a specific
release you can checkout that tag:

```sh
git checkout 2022.5
```

If you want to list all the tags in reverse order:

```sh
git tag --sort=-creatordate
```

#### Building

Build a debug version of Santa:

```sh
bazel build //Source/gui:Santa
```

This will build and sign all of the santa components (UI and services).

For developers who do not have access to Google's code signing certificate and
provisioning profiles, use the `--define=SANTA_BUILD_TYPE=adhoc` flag. This will
adhoc sign Santa and does not require provisioning profiles.

Note: In order to run an adhoc signed Santa SIP must be disabled. See the
running section below.

```sh
bazel build //Source/gui:Santa --define=SANTA_BUILD_TYPE=adhoc
```

#### Running

When working on Santa, it's useful to have a way to quickly reload all of the
Santa components. For this reason, there's a special rule in the Santa BUILD
file that will build Santa, unload Santa if it's running, install the new
Santa in the right place and attempt to load it.

Non-adhoc debug builds of Santa can only be run by Google developers. This is
because of bundle id and provisioning profile restrictions bound to Apple
developer accounts.

```sh
bazel run :reload
```

Non-Google developers can use an adhoc build to run development builds of Santa.
System Integrity Protection (SIP) will need to be disabled in order to run an
adhoc build.

**This is only to be done a machine that is actively developing Santa.**

1.  Boot into Recovery Mode:
    *   For Intel Macs reboot and hold down `command+r`.
    *   For Apple Silicon Macs press and hold the power button until “Loading
        startup options” appears. Click Options, then click Continue. If asked,
        select a volume to recover, then click Next.
2.  From the utilities menu select `Terminal`
3.  Disable the KEXT feature of SIP. The kext wording is legacy but the command
    still works well for loading adhoc signed system extensions: `csrutil enable
    --without kext`
4.  Reboot

You should now be able to load and run a non-release version of Santa.

Build and run an adhoc debug version of Santa.

```sh
bazel run :reload --define=SANTA_BUILD_TYPE=adhoc
```

Note: if you are currently running a release or non-adhoc dev build of Santa,
this new adhoc build will show up as a second instance of Santa. Remove the
non-adhoc instance like so:

```sh
systemextensionsctl uninstall EQHXZ8M8AV com.google.santa.daemon
```

#### IDE Setup

We don't generally use Xcode when working on Santa but it's very useful to be
able to use an IDE when developing. We generally use clangd for this, using a
tool that will extract the appropriate compile commands automatically from our
Bazel build rules. To use this:

1) Run `bazel run @hedron_compile_commands//:refresh_all` to generate the
   `compile_commands.json` file.

2) Follow the [instructions](https://github.com/hedronvision/bazel-compile-commands-extractor#editor-setup--for-autocomplete-based-on-compile_commandsjson)
   for setting up your editor.

#### Debugging

lldb can be used to debug Santa, similarly to any other project, with some
exceptions. lldb can attach to com.google.santa.daemon, however any breakpoints
in the decision making codepath can deadlock the machine.

#### Tests

Run all the logic / unit tests

```sh
bazel test :unit_tests --define=SANTA_BUILD_TYPE=adhoc --test_output=errors
```

##### Testing Config Options Using `/var/db/santa/config-overrides.plist`

Debug versions of Santa have the ability to set/override config settings using an override file, that will be applied over the top of the configuration from a profile.

1. Create a plist in `/var/db/santa/config-overrides.plist`

For example to point Santa at a sync server running on localhost here would be the config-override file.

```xml
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>SyncBaseURL</key>
    <string>http://localhost:8080/v1/santa/</string>
    <key>SyncClientContentEncoding</key>
    <string>gzip</string>
  </dict>
</plist>
```

> :warning: Warning
>  Make sure  the file is readable.

2. run `bazel run //:reload` to rebuild and restart the Santa daemon.

#### Releases

Creates a release build of Santa with a version based of the newest tag. Also
saves the dsym files for each component of Santa. This makes debugging and
interpreting future crashes much easier. Releases are handled by Google internal
infrastructure.

```sh
bazel build --apple_generate_dsym -c opt //:release
```

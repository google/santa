load("@build_bazel_rules_apple//apple:versioning.bzl", "apple_bundle_version")
load("//:helper.bzl", "run_command")
load("//:version.bzl", "SANTA_VERSION")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

exports_files(["LICENSE"])

# The version label for mac_* rules.
apple_bundle_version(
    name = "version",
    build_version = SANTA_VERSION,
    short_version_string = SANTA_VERSION,
)

# Used to detect optimized builds
config_setting(
    name = "opt_build",
    values = {"compilation_mode": "opt"},
)

################################################################################
# Loading/Unloading/Reloading
################################################################################
run_command(
    name = "unload",
    cmd = """
sudo launchctl unload /Library/LaunchDaemons/com.google.santad.plist 2>/dev/null
sudo launchctl unload /Library/LaunchDaemons/com.google.santa.bundleservice.plist 2>/dev/null
sudo kextunload -b com.google.santa-driver 2>/dev/null
launchctl unload /Library/LaunchAgents/com.google.santa.plist 2>/dev/null
""",
)

run_command(
    name = "load",
    cmd = """
sudo launchctl load /Library/LaunchDaemons/com.google.santad.plist
sudo launchctl load /Library/LaunchDaemons/com.google.santa.bundleservice.plist
launchctl load /Library/LaunchAgents/com.google.santa.plist
""",
)

run_command(
    name = "reload",
    srcs = [
        "//Source/santa:Santa",
        "//Source/santa_driver",
    ],
    cmd = """
set -e

rm -rf /tmp/bazel_santa_reload
unzip -d /tmp/bazel_santa_reload \
    $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/Source/santa_driver/santa_driver.zip >/dev/null
unzip -d /tmp/bazel_santa_reload \
    $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/Source/santa/Santa.zip >/dev/null
echo "You may be asked for your password for sudo"
sudo BINARIES=/tmp/bazel_santa_reload CONF=$${BUILD_WORKSPACE_DIRECTORY}/Conf \
    $${BUILD_WORKSPACE_DIRECTORY}/Conf/install.sh
rm -rf /tmp/bazel_santa_reload
echo "Time to stop being naughty"
""",
)

################################################################################
# Release rules - used to create a release tarball
################################################################################
genrule(
    name = "release",
    srcs = [
        "//Source/santa:Santa",
        "//Source/santa_driver",
        "Conf/install.sh",
        "Conf/uninstall.sh",
        "Conf/com.google.santa.bundleservice.plist",
        "Conf/com.google.santad.plist",
        "Conf/com.google.santa.plist",
        "Conf/com.google.santa.asl.conf",
        "Conf/com.google.santa.newsyslog.conf",
        "Conf/Package/Makefile",
        "Conf/Package/postinstall",
        "Conf/Package/preinstall",
    ],
    outs = ["santa-" + SANTA_VERSION + ".tar.gz"],
    cmd = select({
        "//conditions:default": """
        echo "ERROR: Trying to create a release tarball without optimization."
        echo "Please add '-c opt' flag to bazel invocation"
        """,
        ":opt_build": """
      # Extract santa_driver.zip and Santa.zip
      for SRC in $(SRCS); do
        if [ "$$(basename $${SRC})" == "santa_driver.zip" -o "$$(basename $${SRC})" == "Santa.zip" ]; then
          mkdir -p $(@D)/binaries
          unzip -q $${SRC} -d $(@D)/binaries >/dev/null
        fi
      done

      # Copy config files
      for SRC in $(SRCS); do
        if [[ "$$(dirname $${SRC})" == *"Conf" ]]; then
          mkdir -p $(@D)/conf
          cp $${SRC} $(@D)/conf/
        fi
      done

      # Gather together the dSYMs. Throw an error if no dSYMs were found
      for SRC in $(SRCS); do
        case $${SRC} in
          *santa-driver.kext.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santa-driver.kext.dSYM
            ;;
          *santad.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santad.dSYM
            ;;
          *santactl.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santactl.dSYM
            ;;
          *santabundleservice.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santabundleservice.dSYM
            ;;
          *Santa.app.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/Santa.app.dSYM
            ;;
          *com.google.santa.daemon.systemextension.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/com.google.santa.daemon.systemextension.dSYM
            ;;
        esac
      done

      # Cause a build failure if the dSYMs are missing.
      if [[ ! -d "$(@D)/dsym" ]]; then
        echo "dsym dir missing: Did you forget to use --apple_generate_dsym?"
        echo "This flag is required for the 'release' target."
        exit 1
      fi

      # Update all the timestamps to now. Bazel avoids timestamps to allow
      # builds to be hermetic and cacheable but for releases we want the
      # timestamps to be more-or-less correct.
      find $(@D)/{binaries,conf,dsym} -exec touch {} \\;

      # Create final output tar
      tar -C $(@D) -czpf $(@) binaries dsym conf
    """,
    }),
    heuristic_label_expansion = 0,
)

test_suite(
    name = "unit_tests",
    tests = [
        "//Source/common:SNTFileInfoTest",
        "//Source/common:SNTPrefixTreeTest",
        "//Source/santa_driver:SantaCacheTest",
        "//Source/santactl:SNTCommandFileInfoTest",
        "//Source/santactl:SNTCommandSyncTest",
        "//Source/santad:SNTEventTableTest",
        "//Source/santad:SNTExecutionControllerTest",
        "//Source/santad:SNTRuleTableTest",
    ],
)

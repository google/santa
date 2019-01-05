package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

exports_files(["LICENSE"])

load(
    "@build_bazel_rules_apple//apple:macos.bzl",
    "macos_application",
    "macos_kernel_extension",
    "macos_command_line_application",
    "macos_unit_test",
    "macos_xpc_service",
)
load("@build_bazel_rules_apple//apple:versioning.bzl", "apple_bundle_version")
load("//:cmd.bzl", "run_command")

# The version for all Santa components.
SANTA_VERSION = "0.9.30"

# The version label for mac_* rules.
apple_bundle_version(
    name = "version",
    build_version = SANTA_VERSION,
    short_version_string = SANTA_VERSION,
)

# Used to detect optimized builds
config_setting(
  name = "opt_build",
  values = { "compilation_mode": "opt" },
)

################################################################################
# santa-driver rules
################################################################################
cc_library(
    name = "santa-driver_lib",
    srcs = [
        "Source/common/SNTKernelCommon.h",
        "Source/common/SNTLogging.h",
        "Source/santa-driver/main.cc",
        "Source/santa-driver/SantaCache.h",
        "Source/santa-driver/SantaDecisionManager.h",
        "Source/santa-driver/SantaDecisionManager.cc",
        "Source/santa-driver/SantaDriver.h",
        "Source/santa-driver/SantaDriver.cc",
        "Source/santa-driver/SantaDriverClient.h",
        "Source/santa-driver/SantaDriverClient.cc",
        "Source/santa-driver/SantaPrefixTree.h",
        "Source/santa-driver/SantaPrefixTree.cc",
    ],
    copts = [
        "-mkernel",
        "-fapple-kext",
        "-ISource/common",
        "-I__BAZEL_XCODE_SDKROOT__/System/Library/Frameworks/Kernel.framework/PrivateHeaders",
        "-I__BAZEL_XCODE_SDKROOT__/System/Library/Frameworks/Kernel.framework/Headers",
    ],
    defines = [
        "KERNEL",
        "KERNEL_PRIVATE",
        "DRIVER_PRIVATE",
        "APPLE",
        "NeXT",
        "SANTA_VERSION="+SANTA_VERSION,
    ],
    alwayslink = 1,
)

# Full santa-driver.kext
macos_kernel_extension(
    name = "santa-driver",
    bundle_id = "com.google.santa-driver",
    infoplists = ["Source/santa-driver/Resources/santa-driver-Info.plist"],
    ipa_post_processor = ":process_kext_bundle",
    minimum_os_version = "10.9",
    version = ":version",
    deps = [":santa-driver_lib"],
    additional_contents = {
        ":santabs": "XPCServices",
        ":SantaGUI": "Resources",
        ":santactl": "MacOS",
        ":santad": "MacOS",
    },
)

# Script used by the santa-driver rule to ensure the embedded Info.plist is
# an XML-format plist instead of Binary as the kernel cannot parse binary plists.
# TODO: Figure out if we can make bazel/apple-rules do this automatically.
genrule(
    name = "process_kext_bundle",
    outs = ["process_kext_bundle.sh"],
    cmd = """/bin/cat <<'EOM' >$(@)
#!/bin/bash
plutil -convert xml1 "$${1}/"*"/Contents/Info.plist"
EOM""",
    executable = 1,
)

################################################################################
# santactl rules
################################################################################
objc_library(
    name = "santactl_lib",
    srcs = [
        "Source/common/SNTCommonEnums.h",
        "Source/common/SNTConfigurator.h",
        "Source/common/SNTConfigurator.m",
        "Source/common/SNTDropRootPrivs.h",
        "Source/common/SNTDropRootPrivs.m",
        "Source/common/SNTFileInfo.h",
        "Source/common/SNTFileInfo.m",
        "Source/common/SNTKernelCommon.h",
        "Source/common/SNTLogging.h",
        "Source/common/SNTLogging.m",
        "Source/common/SNTRule.h",
        "Source/common/SNTRule.m",
        "Source/common/SNTStoredEvent.h",
        "Source/common/SNTStoredEvent.m",
        "Source/common/SNTStrengthify.h",
        "Source/common/SNTSystemInfo.h",
        "Source/common/SNTSystemInfo.m",
        "Source/common/SNTXPCBundleServiceInterface.h",
        "Source/common/SNTXPCControlInterface.h",
        "Source/common/SNTXPCControlInterface.m",
        "Source/common/SNTXPCSyncdInterface.h",
        "Source/common/SNTXPCSyncdInterface.m",
        "Source/common/SNTXPCUnprivilegedControlInterface.h",
        "Source/common/SNTXPCUnprivilegedControlInterface.m",
        "Source/santad/SNTCachedDecision.h",
        "Source/santactl/SNTCommand.h",
        "Source/santactl/SNTCommand.m",
        "Source/santactl/SNTCommandController.h",
        "Source/santactl/SNTCommandController.m",
        "Source/santactl/main.m",
        "Source/santactl/Commands/SNTCommandFileInfo.m",
        "Source/santactl/Commands/SNTCommandRule.m",
        "Source/santactl/Commands/SNTCommandStatus.m",
        "Source/santactl/Commands/SNTCommandVersion.m",
        "Source/santactl/Commands/sync/NSData+Zlib.h",
        "Source/santactl/Commands/sync/NSData+Zlib.m",
        "Source/santactl/Commands/sync/SNTCommandSync.m",
        "Source/santactl/Commands/sync/SNTCommandSyncConstants.h",
        "Source/santactl/Commands/sync/SNTCommandSyncConstants.m",
        "Source/santactl/Commands/sync/SNTCommandSyncEventUpload.h",
        "Source/santactl/Commands/sync/SNTCommandSyncEventUpload.m",
        "Source/santactl/Commands/sync/SNTCommandSyncLogUpload.h",
        "Source/santactl/Commands/sync/SNTCommandSyncLogUpload.m",
        "Source/santactl/Commands/sync/SNTCommandSyncManager.h",
        "Source/santactl/Commands/sync/SNTCommandSyncManager.m",
        "Source/santactl/Commands/sync/SNTCommandSyncPostflight.h",
        "Source/santactl/Commands/sync/SNTCommandSyncPostflight.m",
        "Source/santactl/Commands/sync/SNTCommandSyncPreflight.h",
        "Source/santactl/Commands/sync/SNTCommandSyncPreflight.m",
        "Source/santactl/Commands/sync/SNTCommandSyncRuleDownload.h",
        "Source/santactl/Commands/sync/SNTCommandSyncRuleDownload.m",
        "Source/santactl/Commands/sync/SNTCommandSyncStage.h",
        "Source/santactl/Commands/sync/SNTCommandSyncStage.m",
        "Source/santactl/Commands/sync/SNTCommandSyncState.h",
        "Source/santactl/Commands/sync/SNTCommandSyncState.m",

    ] + select ({
        ":opt_build": [],
        "//conditions:default": [
            "Source/santactl/Commands/SNTCommandBundleInfo.m",
            "Source/santactl/Commands/SNTCommandCacheHistogram.m",
            "Source/santactl/Commands/SNTCommandCheckCache.m",
            "Source/santactl/Commands/SNTCommandFlushCache.m",
        ],
    }),
    includes = [
        "Source/common",
        "Source/santactl",
        "Source/santactl/Commands",
        "Source/santactl/Commands/sync",
        "Source/santad",
    ],
    sdk_dylibs = ["libz"],
    sdk_frameworks = ["IOKit"],
    deps = [
        "@FMDB//:fmdb",
        "@MOLAuthenticatingURLSession//:MOLAuthenticatingURLSession",
        "@MOLCodesignChecker//:MOLCodesignChecker",
        "@MOLFCMClient//:MOLFCMClient",
        "@MOLXPCConnection//:MOLXPCConnection",
    ],
)

macos_command_line_application(
    name = "santactl",
    bundle_id = "com.google.santactl",
    infoplists = ["Source/santactl/Resources/santactl-Info.plist"],
    minimum_os_version = "10.9",
    version = ":version",
    deps = [":santactl_lib"],
)

################################################################################
# santad rules
################################################################################
objc_library(
    name = "santad_lib",
    srcs = glob([
        "Source/common/*.h",
        "Source/common/*.m",
        "Source/santad/**/*.h",
        "Source/santad/**/*.m",
    ]),
    includes = [
        "Source/common",
        "Source/santad",
        "Source/santad/DataLayer",
        "Source/santad/Logs",
    ],
    sdk_frameworks = [
        "DiskArbitration",
        "IOKit",
    ],
    deps = [
        "@FMDB//:fmdb",
        "@MOLCodesignChecker//:MOLCodesignChecker",
        "@MOLXPCConnection//:MOLXPCConnection",
    ],
)

macos_command_line_application(
    name = "santad",
    bundle_id = "com.google.santad",
    infoplists = ["Source/santad/Resources/santad-Info.plist"],
    minimum_os_version = "10.9",
    version = ":version",
    deps = [":santad_lib"],
)

################################################################################
# santabs rules
################################################################################
objc_library(
    name = "santabs_lib",
    srcs = ["Source/santad/SNTCachedDecision.h"] + glob(
        [
            "Source/common/*.h",
            "Source/common/*.m",
            "Source/santabs/**/*.h",
            "Source/santabs/**/*.m",
        ],
        exclude = [
            "**/SNTBlockMessage.*",
            "**/SNTConfigurator.*",
            "**/SNTDropRootPrivs.*",
            "**/SNTFileWatcher.*",
            "**/SNTSystemInfo.*",
            "**/SNTXPCSyncdInterface.*",
        ],
    ),
    includes = [
        "Source/common",
        "Source/santabs",
        "Source/santad",
    ],
    deps = [
        "@FMDB//:fmdb",
        "@MOLCodesignChecker//:MOLCodesignChecker",
        "@MOLXPCConnection//:MOLXPCConnection",
    ],
)

macos_xpc_service(
    name = "santabs",
    bundle_id = "com.google.santabs",
    infoplists = ["Source/santabs/Resources/santabs-Info.plist"],
    minimum_os_version = "10.9",
    version = ":version",
    deps = [":santabs_lib"],
)

################################################################################
# SantaGUI rules
################################################################################
objc_library(
    name = "SantaGUI_lib",
    srcs = ["Source/santad/SNTCachedDecision.h"] + glob(
        [
            "Source/common/*.h",
            "Source/common/*.m",
            "Source/SantaGUI/**/*.h",
            "Source/SantaGUI/**/*.m",
        ],
        exclude = [
            "**/SNTDropRootPrivs.*",
            "**/SNTFileInfo.*",
            "**/SNTXPCSyncdInterface.*",
        ],
    ),
    includes = [
        "Source/common",
        "Source/santad",
    ],
    sdk_frameworks = [
        "IOKit",
        "SecurityInterface",
    ],
    xibs = glob(["Source/SantaGUI/Resources/*.xib"]),
    deps = [
        "@MOLCodesignChecker//:MOLCodesignChecker",
        "@MOLXPCConnection//:MOLXPCConnection",
    ],
)

macos_application(
    name = "SantaGUI",
    bundle_name = "Santa",
    app_icons = glob(["Source/SantaGUI/Resources/Images.xcassets/**"]),
    bundle_id = "com.google.SantaGUI",
    infoplists = ["Source/SantaGUI/Resources/SantaGUI-Info.plist"],
    minimum_os_version = "10.9",
    version = ":version",
    deps = [":SantaGUI_lib"],
)

################################################################################
# Loading/Unloading/Reloading
################################################################################
run_command(
    name = "unload",
    cmd = """
sudo launchctl unload /Library/LaunchDaemons/com.google.santad.plist 2>/dev/null
sudo kextunload -b com.google.santa-driver 2>/dev/null
launchctl unload /Library/LaunchAgents/com.google.santagui.plist 2>/dev/null
""",
)

run_command(
    name = "load",
    cmd = """
sudo launchctl load /Library/LaunchDaemons/com.google.santad.plist
launchctl load /Library/LaunchAgents/com.google.santagui.plist
""",
)

run_command(
    name = "reload",
    cmd = """
set -e

rm -rf /tmp/bazel_santa_reload
unzip -d /tmp/bazel_santa_reload \
    $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/santa-driver.zip >/dev/null
echo "You may be asked for your password for sudo"
sudo BINARIES=/tmp/bazel_santa_reload CONF=$${BUILD_WORKSPACE_DIRECTORY}/Conf \
    $${BUILD_WORKSPACE_DIRECTORY}/Conf/install.sh
rm -rf /tmp/bazel_santa_reload
echo "Time to stop being naughty"
""",
  srcs = [":santa-driver"],
)


################################################################################
# Release rules - used to create a release tarball
################################################################################
genrule(
    name = "release",
    srcs = [":santa-driver"] + glob(["Conf/**"]),
    outs = ["santa-"+SANTA_VERSION+".tar.gz"],
    cmd = select({
        "//conditions:default": """
        echo "ERROR: Trying to create a release tarball without optimization."
        echo "Please add '-c opt' flag to bazel invocation"
        """,
        ":opt_build": """
      # Extract santa-driver.zip
      for SRC in $(SRCS); do
        if [[ $$(basename $${SRC}) == "santa-driver.zip" ]]; then
          mkdir -p $(@D)/binaries
          unzip -q $${SRC} -d $(@D)/binaries >/dev/null
        fi
      done

      # Copy config files
      for SRC in $(SRCS); do
        if [[ "$$(dirname $${SRC})" == "Conf" ]]; then
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
          *santabs.xpc.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santabs.xpc.dSYM
            ;;
          *Santa.app.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/Santa.app.dSYM
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
      find $(@D)/{binaries,conf,dsym} -exec touch {} \;

      # Create final output tar
      tar -C $(@D) -czpf $(@) binaries dsym conf
    """}),
    heuristic_label_expansion = 0,
)

################################################################################
# Tests
################################################################################
# Compile all the sources instead of using santa*_lib as deps. There are
# duplicate symbols when combining all the components together.
objc_library(
    name = "logic_tests_lib",
    testonly = 1,
    srcs = glob([
        "Source/**/*.h",
        "Source/**/*.m",
        "Tests/LogicTests/*.m",
    ]),
    includes = [
        "Source/common",
        "Source/santabs",
        "Source/santactl",
        "Source/santactl/Commands",
        "Source/santactl/Commands/sync",
        "Source/santad",
        "Source/santad/DataLayer",
        "Source/santad/Logs",
    ],
    resources = glob(
        ["Tests/LogicTests/Resources/**"],
        exclude = [
            "**/BundleExample.app/**",
            "**/DirectoryBundle/**",
        ],
    ),
    sdk_dylibs = ["libz"],
    sdk_frameworks = [
        "AppKit",
        "DiskArbitration",
        "IOKit",
        "SecurityInterface",
    ],
    structured_resources = [
        "Tests/LogicTests/Resources/BundleExample.app",
        "Tests/LogicTests/Resources/DirectoryBundle",
    ],
    deps = [
        "@FMDB//:fmdb",
        "@MOLCodesignChecker//:MOLCodesignChecker",
        "@MOLFCMClient//:MOLFCMClient",
        "@MOLXPCConnection//:MOLXPCConnection",
        "@OCMock//:OCMock",
    ],
)

macos_unit_test(
    name = "logic_tests",
    bundle_id = "com.google.santa.LogicTests",
    minimum_os_version = "10.9",
    deps = [":logic_tests_lib"],
)

objc_library(
    name = "kernel_tests_lib",
    srcs = [
        "Source/common/SNTKernelCommon.h",
        "Tests/KernelTests/main.mm",
    ],
    includes = ["Source/common"],
    sdk_frameworks = [
        "Foundation",
        "IOKit",
    ],
)

macos_command_line_application(
    name = "kernel_tests_bin",
    bundle_id = "com.google.santa.KernelTests",
    minimum_os_version = "10.9",
    deps = [":kernel_tests_lib"],
)

run_command(
    name = "kernel_tests",
    cmd = """
function sigint() {
  echo "\nInterrupted, unloading driver."
  sudo kextunload -b com.google.santa-driver >/dev/null
  exit 1
}
unzip -o $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/santa-driver.zip >/dev/null
echo "Launching Kernel Tests as root. You may be prompted for your sudo password."
trap sigint INT
sudo $${BUILD_WORKSPACE_DIRECTORY}/bazel-bin/kernel_tests_bin
echo "Tests complete, unloading driver."
sudo kextunload -b com.google.santa-driver >/dev/null
""",
    srcs = [
        ":kernel_tests_bin",
        ":santa-driver",
    ],
)

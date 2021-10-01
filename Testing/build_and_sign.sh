#!/bin/sh
set -e

GIT_ROOT=$(git rev-parse --show-toplevel)
TMP_DIR=$(mktemp -d)

function cleanup() {
    # Reset randomize_version if we used it
    if [ -f "$TMP_DIR/version.bzl" ]; then
        mv "$TMP_DIR/version.bzl" $VERSION_FILE
    fi
    rm -rf $TMP_DIR
    rm -f $GIT_ROOT/bazel-bin/santa-*.tar.gz
}
trap cleanup EXIT

function randomize_version() {
    VERSION_FILE="$GIT_ROOT/version.bzl"
    # Create a random version ID for the generated Santa version.
    # The system extension won't replace itself if the version string isn't different than the one
    # presently installed.
    cp $VERSION_FILE $TMP_DIR
    RANDOM_VERSION="$RANDOM.$RANDOM"

    echo "Setting version to $RANDOM_VERSION"
    echo "SANTA_VERSION = \"$RANDOM_VERSION\"" > $VERSION_FILE
}

function build_custom_signed() {
    SANTAD_PATH=Santa.app/Contents/Library/SystemExtensions/com.google.santa.daemon.systemextension/Contents/MacOS/com.google.santa.daemon
    SANTA_BIN_PATH=Santa.app/Contents/MacOS
    KEYCHAIN="santa-dev-test.keychain"
    SANTAD_ENTITLEMENTS="$GIT_ROOT/Source/santad/com.google.santa.daemon.systemextension.entitlements"
    SIGNING_IDENTITY="localhost"

    bazel build --apple_generate_dsym -c opt --define=SANTA_BUILD_TYPE=ci --define=apple.propagate_embedded_extra_outputs=yes --macos_cpus=x86_64,arm64 //:release

    echo "> Build complete, installing santa"
    tar xvf $GIT_ROOT/bazel-bin/santa-*.tar.gz -C $TMP_DIR
    CS_ARGS="--prefix=EQHXZ8M8AV -fs $SIGNING_IDENTITY --timestamp --options library,kill,runtime"

    for bin in $TMP_DIR/binaries/$SANTA_BIN_PATH/*; do
        codesign --keychain $KEYCHAIN --preserve-metadata=entitlements ${CS_ARGS} $bin
    done

    codesign ${CS_ARGS} --keychain $KEYCHAIN --entitlements $SANTAD_ENTITLEMENTS $TMP_DIR/binaries/$SANTAD_PATH
}

function build_provisionprofile_signed() {
    bazel build --apple_generate_dsym -c opt --define=SANTA_BUILD_TYPE=release --define=apple.propagate_embedded_extra_outputs=yes --macos_cpus=x86_64,arm64 //:release
    tar xvf $GIT_ROOT/bazel-bin/santa-*.tar.gz -C $TMP_DIR
}

function build() {
    SANTA_DAEMON_PROVPROFILE=$GIT_ROOT/Source/santad/Santa_Daemon_Dev.provisionprofile
    SANTA_PROVPROFILE=$GIT_ROOT/Source/santa/Santa_Dev.provisionprofile

    if [[ -f $SANTA_DAEMON_PROVPROFILE && -f $SANTA_PROVPROFILE ]]; then
        echo "Using provisionprofiles in $SANTA_DAEMON_PROVPROFILE and $SANTA_PROVPROFILE"
        build_provisionprofile_signed
    else
        echo "No provisionprofiles detected, creating self-signed certs"
        build_custom_signed
    fi
}

function install() {
    echo "> Running install.sh"
    (
        cd $TMP_DIR
        sudo ./conf/install.sh
    )
}

function main() {
    for i in "$@"; do
        case $i in
            --randomize_version)
                randomize_version
                ;;
        esac
    done

    build
    install
}

main $@
exit $?

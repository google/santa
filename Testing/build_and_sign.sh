#!/bin/sh
set -e
GIT_ROOT=$(git rev-parse --show-toplevel)

KEYCHAIN="santa-dev-test.keychain"
SANTAD_PATH=Santa.app/Contents/Library/SystemExtensions/com.google.santa.daemon.systemextension/Contents/MacOS/com.google.santa.daemon
SANTAD_ENTITLEMENTS="$GIT_ROOT/Source/santad/com.google.santa.daemon.systemextension.entitlements"
SANTA_BIN_PATH=Santa.app/Contents/MacOS
SIGNING_IDENTITY="localhost"


function main() {
    bazel build --apple_generate_dsym -c opt --define=SANTA_BUILD_TYPE=ci --define=apple.propagate_embedded_extra_outputs=yes --macos_cpus=x86_64,arm64 //:release

    echo "> Build complete, installing santa"
    TMP_DIR=$(mktemp -d)
    tar xvf $GIT_ROOT/bazel-bin/santa-*.tar.gz -C $TMP_DIR
    CS_ARGS="--prefix=EQHXZ8M8AV -fs $SIGNING_IDENTITY --timestamp --options library,kill,runtime"

    for bin in $TMP_DIR/binaries/$SANTA_BIN_PATH/*; do
        codesign --keychain $KEYCHAIN --preserve-metadata=entitlements ${CS_ARGS} $bin
    done

    codesign ${CS_ARGS} --keychain $KEYCHAIN --entitlements $SANTAD_ENTITLEMENTS $TMP_DIR/binaries/$SANTAD_PATH

    echo "> Running install.sh"
    (
        cd $TMP_DIR
        sudo ./conf/install.sh
    )
}

main $@
exit $?

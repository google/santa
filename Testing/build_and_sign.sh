#!/bin/sh
set -e
GIT_ROOT=$(git rev-parse --show-toplevel)

SANTAD_PATH=Santa.app/Contents/Library/SystemExtensions/com.google.santa.daemon.systemextension/Contents/MacOS/com.google.santa.daemon
SANTA_BIN_PATH=Santa.app/Contents/MacOS
SIGNING_IDENTITY="localhost"

function main() {
    sudo bazel build --ios_signing_cert_name=$SIGNING_IDENTITY --apple_generate_dsym -c opt --define=SANTA_BUILD_TYPE=ci --define=apple.propagate_embedded_extra_outputs=yes --macos_cpus=x86_64,arm64 //:release

    echo "> Build complete, installing santa"
    TMP_DIR=$(mktemp -d)
    tar xvf $GIT_ROOT/bazel-bin/santa-*.tar.gz -C $TMP_DIR

    for bin in $TMP_DIR/binaries/$SANTA_BIN_PATH/* $TMP_DIR/binaries/$SANTAD_PATH; do
        sudo codesign --prefix=EQHXZ8M8AV --preserve-metadata=entitlements -fs $SIGNING_IDENTITY --timestamp --options library,kill,runtime $bin
    done

    echo "> Running install.sh"
    (
        cd $TMP_DIR
        sudo ./conf/install.sh
    )
}

main $@
exit $?

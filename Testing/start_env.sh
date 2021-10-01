#!/bin/sh
set -e

GIT_ROOT=$(git rev-parse --show-toplevel)

SANTA_BIN_PATH=Santa.app/Contents/MacOS
SIGNING_IDENTITY="localhost"

function setup_certs() {
    echo "> Creating codesigning certs and keys"
    $GIT_ROOT/Testing/init_dev_certs.sh init
}

function run_moroz() {
    echo "> Running moroz in the background"
    go get github.com/groob/moroz/cmd/moroz
    ~/go/bin/moroz -configs="$GIT_ROOT/Testing/global.toml" -tls-key santa.key -tls-cert santa.crt &
}

function install_profile() {
    echo "> Installing mobileconfig"
    # The `profiles` tool has been deprecated as of Big Sur. Ugly workaround instead:
    sudo open /System/Library/PreferencePanes/Profiles.prefPane "$GIT_ROOT/Testing/com.google.santa.mobileconfig"
}

function build_install_santa() {
    sudo systemextensionsctl developer on
    echo "> Building and signing Santa"
    $GIT_ROOT/Testing/build_and_sign.sh
    systemextensionsctl list

    # install.sh _should_ already start the system extension, but we want to
    # explicitly call `--load-system-extension` again to actually log loading
    # failures.
    echo "> Install complete, attempting to explicitly start the santa systemextension"
    /Applications/$SANTA_BIN_PATH/Santa --load-system-extension
    systemextensionsctl list
}

function main() {
    install_profile
    setup_certs
    run_moroz
    build_install_santa
}

main $@
exit $?

#!/bin/sh
set -e
GIT_ROOT=$(git rev-parse --show-toplevel)
CNF_PATH=$GIT_ROOT/Testing/openssl.cnf
KEYCHAIN="santa-dev-test.keychain"

function init() {
    openssl genrsa -out ./santa.key 2048
    openssl rsa -in ./santa.key -out ./santa.key
    openssl req -new -key ./santa.key -out ./santa.csr -config $CNF_PATH
    openssl x509 -req -days 10 -in ./santa.csr -signkey ./santa.key -out ./santa.crt -extfile $CNF_PATH -extensions codesign
    openssl pkcs12 -export -out santa.p12 -inkey santa.key -in santa.crt -password pass:santa

    security create-keychain -p santa $KEYCHAIN
    security import ./santa.p12 -k $KEYCHAIN -A -P santa
    security add-trusted-cert -d -r trustRoot -k $KEYCHAIN santa.crt
}

function cleanup() {
    security delete-keychain $KEYCHAIN
    rm santa.key
    rm santa.csr
    rm santa.p12
}

function main() {
    case $1 in
        init)
            init
            ;;
        cleanup)
            cleanup
            ;;
        *)
            echo "$0 [init|cleanup]"
            ;;
    esac
}

main $@
exit $?

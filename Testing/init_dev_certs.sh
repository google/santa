#!/bin/sh
set -e
GIT_ROOT=$(git rev-parse --show-toplevel)
CNF_PATH=$GIT_ROOT/Testing/openssl.cnf

openssl genrsa -out ./santa.key 2048
openssl rsa -in ./santa.key -out ./santa.key
openssl req -new -key ./santa.key -out ./santa.csr -config $CNF_PATH
openssl x509 -req -days 10 -in ./santa.csr -signkey ./santa.key -out ./santa.crt -extfile $CNF_PATH -extensions codesign
openssl pkcs12 -export -out santa.p12 -inkey santa.key -in santa.crt -password pass:santa

KEYCHAIN="/Library/Keychains/System.keychain"
sudo security import ./santa.p12 -k $KEYCHAIN -A -P santa
sudo security add-trusted-cert -d -r trustRoot -k $KEYCHAIN santa.crt

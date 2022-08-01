#!/bin/sh
set -e

openssl genrsa -out server.key 2048
openssl rsa -in server.key -out server.key
openssl req -sha256 -new -key server.key -out server.csr -subj "/CN=santa"
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
rm -f server.csr

sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" server.crt
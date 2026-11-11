#!/bin/sh
# Copyright 2026 Salesforce, Inc. All rights reserved.
set -eu
umask 077
cd "$1"
# Self-signed private roots and a server leaf are generated anew for every case.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -keyout ca.key -out ca.crt -subj /CN=DQ-local-test-root \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -keyout wrong-ca.key -out wrong-ca.crt -subj /CN=DQ-unrelated-test-root \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -keyout server.key -out server.csr -subj /CN=tls-login
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 1 -sha256 -extfile "$2/server.ext"
openssl verify -CAfile ca.crt -verify_hostname tls-login server.crt
openssl verify -CAfile ca.crt -verify_hostname tls-api server.crt
if openssl verify -CAfile wrong-ca.crt server.crt; then exit 1; fi
if openssl verify -CAfile ca.crt -verify_hostname tls-wrong server.crt; then exit 1; fi
# Nginx's root master reads the private key; Flex receives public CA PEM only.
chmod 755 .
chmod 644 server.crt

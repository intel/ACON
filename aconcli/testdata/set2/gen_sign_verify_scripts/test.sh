#!/usr/bin/env bash

# sign somefile using the private key, and with hash algo $1 (i.e. sha256)
openssl dgst -$1 -sign priv.pem -out sig-$1 generate.sh
echo "Generated signature file"

echo "Verify using private key"
openssl dgst -$1 -prverify priv.pem -signature sig-$1 generate.sh

echo "Verify using public key"
openssl dgst -$1 -verify pub.pem -signature sig-$1 generate.sh

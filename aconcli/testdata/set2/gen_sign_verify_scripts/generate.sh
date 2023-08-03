#!/usr/bin/env bash

# generate a private key with 3072 bits key length
openssl genrsa -out priv.pem 3072

# generate corresponding public key
openssl rsa -in priv.pem -pubout -out pub.pem

# create a self-signed certificate
openssl req -new -x509 -key priv.pem -outform der -out cert.der -sha384

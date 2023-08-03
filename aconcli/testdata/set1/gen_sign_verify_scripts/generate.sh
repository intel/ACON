#!/usr/bin/env bash

openssl ecparam -name secp521r1 -genkey -out priv.pem

openssl req -x509 -key priv.pem -outform der -out cert.der

# Copyright © 2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

ACONCLI ?= aconcli
OPENSSL ?= openssl
DOCKER  ?= docker
GO      ?= go
SERVER  ?= sampleserver

all: server.json client/sampleclient

server.json: server/Dockerfile $(wildcard server/src/*cpp) signer.pem signer.cer | .acon/
	$(DOCKER) build -t $(SERVER) -f $< --build-arg https_proxy $(PWD)/../..
	$(ACONCLI) generate -i $(SERVER) $@
	$(ACONCLI) sign -k signer.pem -c signer.cer $@

%.pem:
	$(OPENSSL) ecparam -genkey -name secp384r1 -out $@

%.cer: %.pem
	$(OPENSSL) req -x509 -sha384 -key $< -out $@ -outform der -subj /CN=self-signed-$<

client/sampleclient:
	CGO_ENABLED=0 $(GO) -C $(@D) build -v

.acon/:
	$(ACONCLI) init

clean-server:
	rm -rf .acon/ *.json *.pem *.cer
	$(DOCKER) rmi -f $(SERVER)

clean: clean-server
	$(GO) -C client $@

.PHONY: all clean-server clean

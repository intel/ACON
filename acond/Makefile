# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

OSSL_DIR = $(addsuffix .local,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))
OSSL_INS_DIR = $(addsuffix /ossl3x-acond,$(OSSL_DIR))

ACOND = $(addsuffix target/x86_64-unknown-linux-musl/$(if $(findstring --release,$(CARGO_FLAGS)),release,debug)/acond,\
	    $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))
ACOND_DEST = /usr/bin/acond

build: |$(OSSL_INS_DIR)
	@rustup target add x86_64-unknown-linux-musl
	@OPENSSL_DIR=$(OSSL_INS_DIR) RUSTFLAGS="--deny warnings" cargo build $(CARGO_FLAGS) -v

install: build
	@cp $(ACOND) $(ACOND_DEST)

test: |$(OSSL_INS_DIR)
	@OPENSSL_DIR=$(OSSL_INS_DIR) RUSTFLAGS="--deny warnings" cargo test $(MOD)

clean:
	@cargo clean

distclean: clean
	@rm -fr $(OSSL_DIR)

$(OSSL_DIR):
	@mkdir -p $@

$(OSSL_INS_DIR): |$(OSSL_DIR)
	@rm -fr $|/openssl && git clone --depth 1 --branch openssl-3.1.1 https://github.com/openssl/openssl.git $|/openssl
	@cd $|/openssl && \
	CC=musl-gcc ./config --prefix=$@ -static --with-rand-seed=rdcpu no-engine no-async no-deprecated enable-fips \
	no-gost no-legacy no-threads no-aria no-bf no-blake2 no-camellia no-cast no-chacha no-des no-dsa no-idea no-md4 \
	no-mdc2 no-poly1305 no-rc2 no-rc4 no-rmd160 no-scrypt no-whirlpool no-seed no-shared no-comp no-dso no-dgram no-sm2 \
	no-sm3 no-sm4 no-dh no-ecdh no-ssl no-tls no-ssl-trace no-tls1-method no-tls1_1-method no-tls1_2-method \
	no-dtls1-method no-dtls1_2-method -idirafter/usr/include/x86_64-linux-gnu/ -idirafter/usr/include -fPIE && \
	make && make install_sw && cd -

.PHONY: build \
	install \
	test \
	clean \
	distclean

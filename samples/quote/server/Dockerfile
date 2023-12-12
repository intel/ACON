# Copyright © 2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

#
# This file is used by ../Makefile to build the sample server
#

FROM alpine:latest AS builder

RUN apk update && apk add g++ libc++-static
WORKDIR /work
COPY sdk/ samples/quote/server/ ./
RUN c++ -std=c++14 -Os -static-pie -flto -Iinclude/ -Wl,--gc-sections,-s src/quote_server.cpp -o quote_server

FROM scratch

COPY --from=builder /work/quote_server /
ENTRYPOINT ["/quote_server"]

#!/bin/sh
# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

cc_hack() {
    local a
    set -- $CC_HACK_PREPEND $(for arg; do
        a=
        for sub in $CC_HACK_SUBSTITUTE; do
            test "$sub" = "${sub#$arg=>}" || a="$a ${sub#$arg=>}"
        done
        printf '%s\n' ${a:-$arg}
    done) $CC_HACK_APPEND

    exec ${CC:-cc} "$@"
}

alpine_linker() {
    CC_HACK_SUBSTITUTE="-lgcc_s=>-lgcc_eh" cc_hack "$@"
}

build_with_os_overrides() {
    local readonly rsfl=$(printf '%s\n' \
        $(for p in linker; do
            test -x ${0%/*}/${ID}_$p && echo "-C$p=$(readlink -f ${0%/*})/${ID}_$p"
        done) \
        $CARGO_BUILD_RUSTFLAGS |
        sort -u)

    CARGO_BUILD_RUSTFLAGS=$rsfl exec cargo build "$@"
}

build_static_musl() {
    build_with_os_overrides "$@"
}

build_dynamic_musl() {
    CARGO_BUILD_RUSTFLAGS=-Ctarget-feature=-crt-static build_with_os_overrides "$@"
}

build_static_gnu() {
    CARGO_BUILD_RUSTFLAGS=-Ctarget-feature=+crt-static build_with_os_overrides "$@"
}

build_dynamic_gnu() {
    build_with_os_overrides "$@"
}

build() {
    cd ${0%/*} && build_${B:-dynamic}_$(rustup show | awk '$NF=="(default)" { gsub(/.+-/,"",$1); print $1 }') "$@"
}

build_static() {
    B=static build "$@"
}

build_dynamic() {
    B=dynamic build "$@"
}

. /etc/os-release
${0##*/} "$@"
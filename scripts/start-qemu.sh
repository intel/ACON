#!/bin/sh
# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

command -v qemu || {
    echo $0: \'qemu\' not found in '$PATH'! Please create symlink   \
        \'$HOME/bin/qemu\' pointing to the QEMU executable of your choice.>&2
    exit 1
}

host_fwd() {
    local fwd_rules=
    for v in $(echo $1|cut -d, -f1- --output-delimiter=' '); do
        fwd_rules=$fwd_rules,hostfwd=tcp::${v%%:*}-:${v##*:}
    done
    echo $fwd_rules
}

vdrives() {
    for v in $(echo $1|cut -d, -f1- --output-delimiter=' '); do
        echo "-drive if=virtio,file=$v,format=${v##*.}"
    done
}

initrd() {
    test "x$1" != "x-" && echo "-initrd $1"
}

eval exec qemu -nographic                                                                       \
    -accel kvm                                                                                  \
    ${TD:+-object tdx-guest,id=tdx}                                                             \
    ${TD:+-object memory-backend-memfd-private,id=ram1,size=${M:-2g}}                         \
    -machine q35${TD:+,memory-backend=ram1,kernel_irqchip=split,confidential-guest-support=tdx} \
    -cpu host,-kvm-steal-time,pmu=off                                                           \
    ${VP:+-smp $VP}                                                                             \
    -m ${M:-2g}                                                                               \
    -nodefaults -vga none -no-hpet                                                              \
    -nic user,model=virtio,ipv6=off,ipv4=on,hostname=${TD:+td-}${TD:-vm}$(host_fwd $TCPFWD)     \
    ${CID:+-device vhost-vsock-pci,guest-cid=$(test $CID -gt 2 && echo $CID || echo $$)}        \
    $(vdrives $DRV)                                                                             \
    -bios ${BIOS:-/usr/share/qemu/OVMF.fd}                                                      \
    -chardev stdio,id=mux,mux=on,signal=off                                                     \
    -device virtio-serial,max_ports=1 -device virtconsole,chardev=mux                           \
    -serial chardev:mux                                                                         \
    -monitor chardev:mux                                                                        \
    -append \"ip=dhcp console=hvc0 earlyprintk=ttyS0 $KA\"                                      \
    $(initrd ${RD:-$(dirname $0)/initrd})                                                       \
    -kernel "${@:-$(dirname $0)/vmlinuz}"

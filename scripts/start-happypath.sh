#!/bin/sh
# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

log() {
    local type="$1"; shift
    local text="$*"
    local dt; dt="$(date --rfc-3339=seconds)"
    local color

    case "$type" in
        Note)
            color='\e[32m'  # Green color for notes
            ;;
        Warn)
            color='\e[33m'  # Yellow color for warnings
            ;;
        ERROR)
            color='\e[31m'  # Red color for errors
            ;;
    esac

    # Reset color at the end of the message
    local reset_color='\e[m'

    echo -e "$dt $color[$type] $text$reset_color"
}

log_note() {
    log Note "$@"
}

log_warn() {
    log Warn "$@" >&2
}

log_error() {
    log ERROR "$@" >&2
}

get_options() {
    while getopts "d:i:f:j:h" opt; do
        case $opt in
            d) bundle_dir="$OPTARG";;
            i) docker_id="$OPTARG";;
            f) docker_file="$OPTARG";;
            j) jq_string="$OPTARG";;
            h) opt_h=1
               echo "Usage: run_workload -d bundle_dir -i container -f docker_file [-h]"
               ;;
            \?) echo "Invalid option: -$OPTARG" >&2
                exit 1
                ;;
        esac
    done
}

run_workload() {
    get_options "$@"

    if [ "$opt_h" == 1 ]; then
        return 0
    fi

    test -v "$jq_string" || {
        jq_string=".writableFS=true"
    }

    test -d "$bundle_dir" && {
        log_warn "$bundle_dir directory already exist and will be cleared" 
        rm -rf $bundle_dir
    }

    local readonly acon_root=$(git rev-parse --show-toplevel)
    test -d "$acon_root" || {
        log_error "Failed to deduce ACON root from current directory"
        return 2
    }

    log_note "Prepare kernel.img and OVMF.fd"
    git clone https://github.com/billionairiam/KernelAndOVFD.git $bundle_dir || {
        log_error "Failed to clone the repository."
        return 2
    }
    

    log_note "Build aconcli"
    cd "$acon_root/aconcli" && go generate && go build || {
        log_error "Build aconcli error."
        return 2
    }

    log_note "Build acond"
    source "$acon_root/scripts/acon-build.env" && U=. start_rust_buildenv -- ./build_static -r || {
        log_error "Build acond error or timeout"
        return 2
    }
    

    log_note "Generate initrd"
    cd ../$bundle_dir && mkdir initrd.d && INIT=/bin/acond gen_initrd initrd.d busybox:latest || {
        log_error "gen_initrd failed"
        return 2
    }

    log_note "Create initrd"
    cp "$acon_root/acond/target/release/acond" initrd.d/bin/acond
    create_initrd initrd.d/ ./initrd.img || {
        log_error "create_initrd failed"
    }

    log_note "Init bundle directory"
    cp "$acon_root/aconcli/aconcli" . && ./aconcli init . || {
        log_error "Init bundle directory error"
        return 2
    }

    log_note "Build bundle"
    if test -n "$docker_file"; then
        docker build -f "$docker_file" -t "$docker_id" .
    else
        docker pull "$docker_id"
    fi

    log_note "Generate Manifest"
    ./aconcli generate -o "$docker_id.json" "$docker_id" || {
        log_error "Generate Manifest error"
        return 2
    }

    log_note "Modify manifest file"
    cat <<< $(jq "$jq_string" "$docker_id.json") > "$docker_id.json" || {
        log_error "Append WritableFs:true to manifest failed"
        return 2
    }

    log_note "Generate KEY and CER"
    openssl ecparam -name secp521r1 -genkey -out signer.pem && openssl req -x509 -sha384 -key \
    signer.pem -outform der -out signer.cer -subj /C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com

    log_note "Sign Manifest"
    ./aconcli sign -c signer.cer -k signer.pem "$docker_id.json" || {
        log_error "Sign Manifest error"
        return 2
    }

    log_note "run TDVM"
    ATD_BIOS=OVMF.fd ATD_KERNEL=kernel.img ATD_RD=initrd.img ./aconcli run -n "$docker_id.json" -c :5532 -f "$acon_root/scripts/acon-startvm" || {
        log_error "Run TDVM error will stop ACON instances"
        ./aconcli shutdown -f tcp://:5532
        return 2
    }

    log_note "Get TDVM status"
    ./aconcli status

    log_note "Invoke TDVM"
    ./aconcli invoke -c tcp://:5532 -e 1 Whoami

    log_note "Stop ACON instances"
    ./aconcli shutdown -f tcp://:5532
}

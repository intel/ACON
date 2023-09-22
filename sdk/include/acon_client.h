// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#ifndef _ACON_CLIENT_H_
#define _ACON_CLIENT_H_

#define SOCKET_PATH "/shared/acon.sock"

typedef struct {
    char type;
    char subtype;
    char version;
    char _reserved;
} report_type_t;

typedef struct {
    char cpu_svn[16];
} cpu_svn_t;

typedef struct {
    char hash[48];
} sha384_hash_t;

typedef struct {
    report_type_t report_type;
    char reserved[12];
    cpu_svn_t cpu_svn;
    sha384_hash_t tee_tcb_info_hash;
    sha384_hash_t tee_info_hash;
    char report_data[64];
    char _reserved[32];
    char mac[32];
} report_mac_t;

typedef struct {
    char hash[239];
} tee_tcb_info_t;

typedef struct {
    char attributes[8];
    char xfam[8];
    sha384_hash_t mrtd;
    sha384_hash_t mr_config_id;
    sha384_hash_t mr_owner;
    sha384_hash_t mr_owner_config;
    sha384_hash_t rtmr0;
    sha384_hash_t rtmr1;
    sha384_hash_t rtmr2;
    sha384_hash_t rtmr3;
    char _reserved[112];
} td_info_t;

typedef struct {
    report_mac_t report_mac;
    tee_tcb_info_t tee_tcb_info;
    char _reserved[17];
    td_info_t td_info;
} td_report_t;

typedef struct {
    int command;    // even = request; odd = response; negative = error
    int size;       // size of the whole request/response
} acon_message_hdr_t;

typedef struct {
    acon_message_hdr_t header;  // command = -Exxx, as defintion in Linux
    int request;                // original request code
} acon_message_err_t;

typedef struct {
    acon_message_hdr_t header;  // command = 0
    bool is_quote;
    long long nonce[2];
    int data_type;              // 0 = no data; 1 = binary; 2 = string; others = reserved
} acon_get_report_req_t;

typedef struct {
    acon_message_hdr_t header;   // command = 1
    int rtmr_count;
    td_report_t report;
    int quote_offset;
    int attestation_json_offset;
} acon_get_report_rsp_t;

typedef struct {
    acon_message_hdr_t header;  // command = 2
    int data_type;              // Same definition as acon_get_report_req_t.data_type
} acon_set_attestation_data_req_t;

typedef struct {
    acon_message_hdr_t header;   // command = 3
} acon_set_attestation_data_rsp_t;

union acon_req {
    acon_message_hdr_t header;
    acon_get_report_req_t get_report_req;
    acon_set_attestation_data_req_t set_attestation_data_req;
};

union acon_rsp {
    acon_message_hdr_t header;
    acon_message_err_t error;
    acon_get_report_rsp_t get_report_rsp;
    acon_set_attestation_data_rsp_t set_attestation_data_rsp;
};

#endif

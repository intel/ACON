// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Alias {
    // Aliases refer to objects in acond's content store, such as FS layers.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub contents: HashMap<String, Vec<String>>,
    // Aliases refer to objects defined inside the current Manifest being processed.
    // There's currently only one such object defined - ., which refers to the current Image.
    #[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "self")]
    pub itself: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Policy {
    // Images that are allowed to share eTD with the enclosing Image.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepts: Vec<String>,
    // True to reject all other Images not listed in accepts, default false.
    #[serde(default, rename = "rejectUnaccepted")]
    pub reject_unaccepted: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Manifest {
    // Version of this spec in the form of [ MAJOR, MINOR ], and should be
    // [ 1, 0 ] for version 1.0.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        rename = "aconSpecVersion"
    )]
    pub acon_spec_version: Vec<u32>,
    // This is an array of FS layers from bottom to top (i.e., the same order
    // as in an OCI manifest) to be merged by overlay to form a Container's directory tree.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<String>,
    // This optional field defines Aliases of other objects, which could be
    // either FS layers or Images. More types of Aliases may be added in future.
    pub aliases: Alias,
    // This array of strings is passed to execve(2) syscall as the command arguments
    // to this Image's entry point, whose path is the first element of this same array..
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,
    // This lists environment variables (and optionally their acceptable values) settable
    // by untrusted code when executing this Image's entry point.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    // This is the working directory in which the Image's entrypoint should be executed.
    #[serde(rename = "workingDir")]
    pub working_dir: String,
    // These are additional UIDs that can be switched to by setuid(2) and seteuid(2) syscalls
    // inside a Container (launched from this Image).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uids: Vec<u32>,
    // This field lists file descriptors whose outputs contain no secrets and can be revealed to
    // untrusted entities. Outputs from these file descriptors may be captured by acond and made
    // available through acond's external interface.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "logFDs")]
    pub log_fds: Vec<i32>,
    // True to allow a Container to write to its directory tree, default false.
    #[serde(default, rename = "writableFS")]
    pub writable_fs: bool,
    // True to forbit a Container from being restarted, default false.
    #[serde(default, rename = "noRestart")]
    pub no_restart: bool,
    // This array of integers specifies the signals allowed to be sent by untrusted code,
    // default Empty - No signals are allowed. The first element also specifies the signal
    // to send upon restarting the Container.
    pub signals: Vec<i32>,
    // This must be an integer and is the maximal number of Container instances that can be
    // launched from this Image simultaneously, default 1 (singleton).
    #[serde(default, rename = "maxInstances")]
    pub max_instances: u64,
    // Specifies the Launch Policy that determines what other Images may share the same eTD with this Image.
    pub policy: Policy,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Measurement {
    pub tde: String,
    pub signer: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Image {
    pub id: String,
    pub hash_algorithm: String,
    pub signer_digest: String,
    pub signer_bytes: Vec<u8>,
    pub manifest_digest: String,
    pub manifest: Manifest,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum AttestDataValue {
    NoDataValue {},
    DataValue {
        #[serde(rename = "type")]
        dtype: i32,
        data: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AttestData {
    pub api_version: String,
    pub requestor_nonce: Vec<u8>,
    pub acond_nonce: Vec<u8>,
    pub attestation_data: BTreeMap<String, BTreeMap<u32, AttestDataValue>>,
}

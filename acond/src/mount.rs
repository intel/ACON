// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use nix::mount::MsFlags;

#[derive(Debug, PartialEq)]
pub struct RootMount {
    pub source: Option<&'static str>,
    pub target: &'static str,
    pub fstype: Option<&'static str>,
    pub flags: MsFlags,
    pub option: Option<&'static str>,
}

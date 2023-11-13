// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use anyhow::Result;
use nix::mount::{self, MsFlags};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs as unixfs;
use std::path::Path;

lazy_static! {
    pub static ref SOFT_LINKS: Vec<(&'static str, &'static str)> = vec![
        ("/proc/self/fd", "/dev/fd"),
        ("/proc/self/fd/0", "/dev/stdin"),
        ("/proc/self/fd/1", "/dev/stdout"),
        ("/proc/self/fd/2", "/dev/stderr")
    ];
    pub static ref ROOTFS_MOUNTS: Vec<RootMount> = vec![
        RootMount {
            source: None,
            target: "/dev",
            fstype: Some("devtmpfs"),
            flags: MsFlags::empty(),
            option: None
        },
        RootMount {
            source: None,
            target: "/dev/pts",
            fstype: Some("devpts"),
            flags: MsFlags::empty(),
            option: None
        },
        RootMount {
            source: None,
            target: "/proc",
            fstype: Some("proc"),
            flags: MsFlags::empty(),
            option: None
        },
        RootMount {
            source: None,
            target: "/sys",
            fstype: Some("sysfs"),
            flags: MsFlags::empty(),
            option: None
        },
        RootMount {
            source: None,
            target: "/shared",
            fstype: Some("tmpfs"),
            flags: MsFlags::empty(),
            option: Some("size=1m")
        },
        RootMount {
            source: None,
            target: "/run",
            fstype: Some("tmpfs"),
            flags: MsFlags::empty(),
            option: Some("size=50%,mode=0755")
        },
    ];
}

#[derive(Debug, PartialEq)]
pub struct RootMount {
    pub source: Option<&'static str>,
    pub target: &'static str,
    pub fstype: Option<&'static str>,
    pub flags: MsFlags,
    pub option: Option<&'static str>,
}

pub fn mount_rootfs() -> Result<()> {
    if !utils::is_rootfs_mounted() {
        for m in ROOTFS_MOUNTS.iter() {
            let target = Path::new(m.target);
            if !target.exists() {
                fs::create_dir(target)?;
            }

            mount::mount(m.source, m.target, m.fstype, m.flags, m.option)?;
        }
    }

    for (original, link) in SOFT_LINKS.iter() {
        unixfs::symlink(original, link).or_else(|e| match e {
            ref e if e.kind() == ErrorKind::AlreadyExists => Ok(()),
            _ => Err(e),
        })?;
    }

    Ok(())
}

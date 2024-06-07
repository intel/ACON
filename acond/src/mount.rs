// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use anyhow::Result;
use nix::mount::{self, MsFlags};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, ErrorKind},
    os::unix::fs as unixfs,
    path::Path,
};

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

fn parse_mount_options(options_str: &str) -> (MsFlags, Vec<String>) {
    let mut flags = MsFlags::empty();
    let mut options = Vec::new();

    for option in options_str.split(',') {
        match option {
            "defaults" => (),
            "ro" => flags |= MsFlags::MS_RDONLY,
            "nosuid" => flags |= MsFlags::MS_NOSUID,
            "nodev" => flags |= MsFlags::MS_NODEV,
            "noexec" => flags |= MsFlags::MS_NOEXEC,
            "sync" => flags |= MsFlags::MS_SYNCHRONOUS,
            "remount" => flags |= MsFlags::MS_REMOUNT,
            "dirsync" => flags |= MsFlags::MS_DIRSYNC,
            "diratime" => flags |= MsFlags::MS_NOATIME,
            "nodiratime" => flags |= MsFlags::MS_NODIRATIME,
            "silent" => flags |= MsFlags::MS_SILENT,
            "relatime" => flags |= MsFlags::MS_RELATIME,
            "strictatime" => flags |= MsFlags::MS_STRICTATIME,
            "lazytime" => flags |= MsFlags::MS_LAZYTIME,
            _ if option.contains('=') => options.push(option.into()),
            _ => eprintln!("Mount option '{option}' is not supported."),
        }
    }

    (flags, options)
}

fn mount_fstab() -> Result<()> {
    let fstab_file = File::open("/etc/fstab")?;
    let reader = BufReader::new(fstab_file);

    for line in reader.lines() {
        let line = line?;
        if line.trim().starts_with('#') || line.trim().is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        if fields[2] == "swap" {
            continue;
        } else {
            let target = Path::new(fields[1]);
            if !target.exists() {
                fs::create_dir(target)?;
            }

            let (flags, options) = parse_mount_options(fields[3]);
            mount::mount(
                Some(fields[0]).filter(|s| *s != "none"),
                fields[1],
                Some(fields[2]).filter(|s| *s != "none"),
                flags,
                Some(options.join(",").as_str()).filter(|s| !s.is_empty()),
            )?;
        }
    }

    Ok(())
}

pub fn mount_rootfs() -> Result<()> {
    if !utils::is_rootfs_mounted() && mount_fstab().is_err() {
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

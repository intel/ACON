// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate scopeguard;

use crate::config::Config;
use anyhow::{anyhow, Result};
use nix::{
    sys::reboot::{self, RebootMode},
    unistd::{self, ForkResult, Gid, Pid, Uid},
};
use std::{fs, os::unix::net::UnixStream};
use tokio::runtime::Builder;

mod config;
mod container;
mod image;
mod io;
mod ipc;
mod mount;
mod oidc;
mod pod;
#[cfg(feature = "interactive")]
mod pty;
mod report;
mod restful;
mod server;
mod utils;

fn start_service() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();
    config.parse_cmdline(None)?;

    let (pstream, cstream) = UnixStream::pair()?;

    match unsafe { unistd::fork() } {
        Ok(ForkResult::Parent { child: _ }) => {
            pstream.set_nonblocking(true)?;
            drop(cstream);

            let rt = Builder::new_current_thread().enable_all().build()?;
            rt.block_on(server::start_server(pstream, &config))?;
            rt.shutdown_background();

            Ok(())
        }
        Ok(ForkResult::Child) => {
            let gid = Gid::from_raw(utils::CLIENT_UID);
            let uid = Uid::from_raw(utils::CLIENT_UID);

            fs::create_dir_all(utils::BLOB_DIR)?;
            unistd::chown(utils::BLOB_DIR, Some(uid), Some(gid))?;

            unistd::setresgid(gid, gid, gid)?;
            unistd::setresuid(uid, uid, uid)?;

            prctl::set_name("deprivileged_server").map_err(|e| anyhow!(e.to_string()))?;
            cstream.set_nonblocking(true)?;
            drop(pstream);

            let rt = Builder::new_current_thread().enable_all().build()?;
            rt.block_on(restful::run_server(cstream, &config))?;

            Ok(())
        }
        Err(errno) => {
            eprintln!("Start service error, errno = {errno}.");
            Err("Start service error, errno = {errno}.".into())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Uncomment it to debug.
    // env_logger::init_from_env(env_logger::Env::default().default_filter_or("debug"));
    mount::mount_rootfs()?;

    start_service()?;

    if unistd::getpid() == Pid::from_raw(1) {
        reboot::reboot(RebootMode::RB_POWER_OFF)?;
    }
    Ok(())
}

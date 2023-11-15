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
use std::{env, os::unix::net::UnixStream};
use tokio::runtime::Builder;

mod config;
mod container;
mod image;
mod io;
mod ipc;
mod mount;
mod pod;
#[cfg(feature = "interactive")]
mod pty;
mod report;
mod rpc;
mod server;
mod unix_incoming;
mod utils;
mod vsock_incoming;

fn start_service(debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();
    config.parse_cmdline(None)?;

    let (pstream, cstream) = UnixStream::pair()?;

    match unsafe { unistd::fork() } {
        Ok(ForkResult::Parent { child: _ }) => {
            pstream.set_nonblocking(true)?;
            let rt = Builder::new_current_thread().enable_all().build()?;
            rt.block_on(server::start_server(pstream, &config))?;
            rt.shutdown_background();

            Ok(())
        }
        Ok(ForkResult::Child) => {
            cstream.set_nonblocking(true)?;
            let gid = Gid::from_raw(1);
            let uid = Uid::from_raw(1);
            unistd::setresgid(gid, gid, gid)?;
            unistd::setresuid(uid, uid, uid)?;
            prctl::set_name("rpc_server").map_err(|e| anyhow!(e.to_string()))?;

            let rt = Builder::new_current_thread().enable_all().build()?;
            if debug {
                rt.block_on(rpc::run_unix_server(cstream))?;
            } else if config.vsock_conn {
                rt.block_on(rpc::run_vsock_server(cstream, config.vsock_port))?;
            } else {
                rt.block_on(rpc::run_tcp_server(cstream, config.tcp_port))?;
            }

            Ok(())
        }
        Err(errno) => {
            eprintln!("Start service error, errno = {errno}.");
            Err("Start service error, errno = {errno}.".into())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    mount::mount_rootfs()?;

    let args = env::args().collect::<Vec<_>>();
    let debug = args.len() == 2 && args[1] == "unix";
    start_service(debug)?;

    if unistd::getpid() == Pid::from_raw(1) {
        reboot::reboot(RebootMode::RB_POWER_OFF)?;
    }
    Ok(())
}

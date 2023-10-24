// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate scopeguard;

use crate::config::Config;
use crate::mount::RootMount;
use crate::pod::Pod;
use anyhow::{anyhow, Result};
use futures::future;
use nix::{
    errno::Errno,
    mount::{self as nix_mount, MsFlags},
    sys::{
        reboot::{self, RebootMode},
        wait,
    },
    unistd::{self, Pid},
};

use std::{env, fs, mem, path::Path, sync::Arc};
use tokio::{
    runtime::Builder,
    signal::unix as tokio_unix,
    sync::{mpsc, watch, RwLock},
    task::JoinHandle,
    time::{self, Duration},
};

mod config;
mod container;
mod image;
mod ipc;
mod mount;
mod pod;
#[cfg(feature = "interactive")]
mod pty;
mod report;
mod rpc;
mod unix_incoming;
mod utils;
mod vsock_incoming;

lazy_static! {
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

const ACOND_DEBUG_SOCK_PATH: &str = "/tmp/acon.sock";
const ACOND_SOCK_PATH: &str = "/shared/acon.sock";

async fn handle_signal(pod: Arc<RwLock<Pod>>) -> Result<()> {
    let siginfo = unsafe {
        let mut siginfo: libc::siginfo_t = mem::zeroed();
        Errno::result(libc::waitid(
            libc::P_ALL,
            0,
            &mut siginfo,
            libc::WNOWAIT | libc::WNOHANG | libc::WEXITED,
        ))?;
        siginfo
    };

    let child_pid = unsafe { siginfo.si_pid() };
    if child_pid == 0 {
        return Ok(());
    }

    if utils::is_init_process(child_pid)? {
        let cid = unsafe { siginfo.si_uid() };
        let ref_pod = pod.clone();
        let mut pod = ref_pod.write().await;

        if let Some(c) = pod.get_container_mut(&cid) {
            c.status = container::CStatus::Exited(unsafe { siginfo.si_status() });
            utils::umount_container_rootfs(c.id)?;
            if let Some(exit_notifier) = c.exit_notifier.as_ref() {
                exit_notifier.notify_waiters();
            } else {
                utils::destroy_container_dtree(cid)?;
            }
        }
    }

    wait::waitpid(Pid::from_raw(child_pid), None)?;

    let ref_pod = pod.clone();
    let pod = ref_pod.read().await;
    if !pod.has_alive_container() {
        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(true).await;
        }
    }

    Ok(())
}

async fn setup_signal_handler(
    pod: Arc<RwLock<Pod>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    prctl::set_child_subreaper(true).map_err(|e| anyhow!(e.to_string()))?;

    let mut sigchild = tokio_unix::signal(tokio_unix::SignalKind::child())?;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                break;
            }

            _ = sigchild.recv() => {
                handle_signal(pod.clone()).await?;
            }
        }
    }

    Ok(())
}

async fn start_timer(mut rx: mpsc::Receiver<bool>, timeout: u64) {
    let mut stop = true;
    loop {
        while !stop {
            stop = rx.recv().await.unwrap();
        }

        match time::timeout(Duration::from_secs(timeout), rx.recv()).await {
            Ok(v) => stop = v.unwrap(),
            Err(_) => {
                if stop {
                    break;
                }
            }
        }
    }
}

async fn start_rpc(debug: bool) -> Result<(), Box<dyn std::error::Error>> {
    // log support?

    let mut config = Config::new();
    config.parse_cmdline(None)?;

    let (timeout_tx, timeout_rx) = mpsc::channel(1);
    let pod = Arc::new(RwLock::new(Pod::new(Some(timeout_tx))));

    let mut tasks: Vec<JoinHandle<Result<()>>> = Vec::new();
    let (shutdown_sender, shudown_receiver) = watch::channel(true);

    tasks.push(tokio::spawn(setup_signal_handler(
        pod.clone(),
        shudown_receiver.clone(),
    )));
    tasks.push(tokio::spawn(ipc::run_unix_server(
        pod.clone(),
        ACOND_SOCK_PATH,
        shudown_receiver.clone(),
    )));

    #[cfg(feature = "interactive")]
    {
        let (tx, rx) = mpsc::channel(1);
        tasks.push(tokio::spawn(pty::run_terminal_server(rx)));
        tasks.push(tokio::task::spawn_blocking(move || {
            pty::run_acond_terminal(tx)
        }));
    }

    tokio::select! {
        _ = start_timer(timeout_rx, config.timeout as u64) => (),

        res = async {
            if debug {
                rpc::run_unix_server(pod.clone(), ACOND_DEBUG_SOCK_PATH).await
            } else if config.vsock_conn {
                rpc::run_vsock_server(pod.clone(), config.vsock_port).await
            } else {
                rpc::run_tcp_server(pod.clone(), config.tcp_port).await
            }
        } => {
            return res;
        }
    }

    shutdown_sender.send(true)?;

    future::join_all(tasks).await;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();

    let debug = args.len() == 2 && args[1] == "unix";

    if !utils::is_rootfs_mounted() {
        for m in ROOTFS_MOUNTS.iter() {
            let target = Path::new(m.target);
            if !target.exists() {
                fs::create_dir(target)?;
            }

            nix_mount::mount(m.source, m.target, m.fstype, m.flags, m.option)?;
        }
    }

    let rt = Builder::new_current_thread().enable_all().build()?;
    rt.block_on(start_rpc(debug))?;
    rt.shutdown_background();

    if unistd::getpid() == Pid::from_raw(1) {
        reboot::reboot(RebootMode::RB_POWER_OFF)?;
    }

    Ok(())
}

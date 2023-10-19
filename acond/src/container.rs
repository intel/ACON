// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "interactive")]
use crate::pty as tdpty;
use crate::{
    image::{AttestDataValue, Image},
    mount::RootMount,
    utils::{self, BUFF_SIZE},
};
use anyhow::{anyhow, Result};
#[cfg(feature = "interactive")]
use nix::pty;
use nix::{
    errno::Errno,
    fcntl::{self, FcntlArg, FdFlag, OFlag},
    libc,
    mount::{self, MsFlags},
    sched::{self, CloneFlags},
    sys::{stat::Mode, wait},
    unistd::{self, ForkResult, Gid, Pid, Uid},
};
#[cfg(not(feature = "interactive"))]
use std::os::unix::io::{FromRawFd, RawFd};
use std::{collections::HashMap, env, ffi::CString, fs, mem, path::Path, process, sync::Arc};
use tokio::sync::Notify;
#[cfg(not(feature = "interactive"))]
use tokio::{
    self,
    fs::File,
    io,
    time::{self, Duration},
};

pub const MAX_BUFF_LEN: usize = 128 * BUFF_SIZE;
const EPPATH: &str = "/lib/acon/entrypoint.d/";

lazy_static! {
    pub static ref ROOTFS_MOUNTS: Vec<RootMount> = vec![
        RootMount {
            source: Some("/dev"),
            target: "dev",
            fstype: None,
            flags: MsFlags::MS_NOSUID | MsFlags::MS_BIND | MsFlags::MS_REC,
            option: None
        },
        RootMount {
            source: Some("/shared"),
            target: "shared",
            fstype: None,
            flags: MsFlags::MS_NOSUID | MsFlags::MS_BIND | MsFlags::MS_NODEV,
            option: Some("mode=1777")
        },
        RootMount {
            source: None,
            target: "proc",
            fstype: Some("proc"),
            flags: MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            option: None
        },
        RootMount {
            source: None,
            target: "tmp",
            fstype: Some("tmpfs"),
            flags: MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            option: Some("mode=1777")
        },
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CStatus {
    Running(u32),
    Exited(i32),
}

#[derive(Debug)]
pub struct Container {
    pub id: u32,
    pub pid: Pid,
    pub status: CStatus,
    pub image_id: String,
    pub exec_path: String,
    pub envs: Option<Vec<String>>,
    pub uids: Option<HashMap<u32, u32>>,
    pub attest_data: AttestDataValue,
    pub exit_notifier: Option<Arc<Notify>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecArgs {
    args: Vec<String>,
    envs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigArgs {
    overlay_fs: String,
    writable_fs: bool,
    work_dir: String,
    uids: HashMap<u32, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForkArgs {
    container_id: u32,
    child_pid: Option<Pid>,
    config_args: Option<ConfigArgs>,
    exec_args: ExecArgs,
    stdin: Option<i32>,
    stdout: Option<i32>,
    stderr: Option<i32>,
}

impl Container {
    pub async fn start(image: &Image, envs: &Vec<String>) -> Result<Self> {
        let container_id = utils::generate_cid()?;
        let overlay_fs = utils::setup_container_dtree(image, container_id)?;

        let env_vars = utils::get_env_vars(&image.manifest.env, envs)?;
        let mut uids = HashMap::new();
        uids.insert(0, container_id);
        for uid in image.manifest.uids.iter() {
            let ruid = utils::generate_cid()?;
            uids.insert(*uid, ruid);
        }

        let fork_args = ForkArgs {
            container_id,
            child_pid: None,
            config_args: Some(ConfigArgs {
                overlay_fs,
                writable_fs: image.manifest.writable_fs,
                work_dir: image.manifest.working_dir.clone(),
                uids: uids.clone(),
            }),
            exec_args: ExecArgs {
                args: image.manifest.entrypoint.to_vec(),
                envs: env_vars.to_vec(),
            },
            stdin: None,
            stdout: None,
            stderr: None,
        };

        let child_pid = create_child(&fork_args)?;

        let exit_notifier = if image.manifest.no_restart {
            None
        } else {
            Some(Arc::new(Notify::new()))
        };

        Ok(Container {
            id: container_id,
            pid: child_pid,
            status: CStatus::Running(0),
            image_id: image.id.clone(),
            exec_path: image.manifest.entrypoint[0].clone(),
            envs: Some(env_vars),
            uids: Some(uids),
            attest_data: AttestDataValue::NoDataValue {},
            exit_notifier,
        })
    }

    pub async fn restart(&mut self, image: &Image) -> Result<()> {
        let overlay_fs = utils::setup_container_dtree(image, self.id)?;
        let fork_args = ForkArgs {
            container_id: self.id,
            child_pid: None,
            config_args: Some(ConfigArgs {
                overlay_fs,
                writable_fs: image.manifest.writable_fs,
                work_dir: image.manifest.working_dir.clone(),
                uids: self.uids.clone().unwrap(),
            }),
            exec_args: ExecArgs {
                args: image.manifest.entrypoint.to_vec(),
                envs: self.envs.clone().unwrap(),
            },
            stdin: None,
            stdout: None,
            stderr: None,
        };

        self.pid = create_child(&fork_args)?;
        self.status = CStatus::Running(0);

        Ok(())
    }

    pub async fn enter(
        &self,
        command: &str,
        arguments: &[String],
        envs: &[String],
        _timeout: u64,
        _buff: &[u8],
        _capture_size: usize,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let entryp = format!("{}{}", EPPATH, command);
        let mut args = vec![entryp];

        for arg in arguments.iter() {
            args.push(arg.clone());
        }

        #[cfg(feature = "interactive")]
        {
            let fork_args = ForkArgs {
                container_id: self.id,
                child_pid: Some(self.pid),
                config_args: None,
                exec_args: ExecArgs {
                    args,
                    envs: envs.iter().map(|var| var.clone()).collect::<Vec<_>>(),
                },
                stdin: None,
                stdout: None,
                stderr: None,
            };

            create_child(&fork_args)?;

            return Ok((vec![], vec![]));
        }

        #[cfg(not(feature = "interactive"))]
        if _timeout == 0 {
            Err(anyhow!(utils::ERR_RPC_INVALID_TIMEOUT))
        } else {
            let (crdstdin, pwrstdin) = unistd::pipe()?;
            fcntl::fcntl(pwrstdin, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

            let (prdstdout, cwrstdout) = unistd::pipe()?;
            fcntl::fcntl(prdstdout, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

            let (prdstderr, cwrstderr) = unistd::pipe()?;
            fcntl::fcntl(prdstderr, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;

            let fork_args = ForkArgs {
                container_id: self.id,
                child_pid: Some(self.pid),
                config_args: None,
                exec_args: ExecArgs {
                    args,
                    envs: envs.to_vec(),
                },
                stdin: Some(crdstdin),
                stdout: Some(cwrstdout),
                stderr: Some(cwrstderr),
            };

            create_child(&fork_args)?;

            poll_output(
                pwrstdin,
                prdstdout,
                prdstderr,
                _buff,
                _timeout,
                _capture_size,
            )
            .await
        }
    }

    pub fn update_status(&mut self) -> Result<()> {
        if !self.is_running() {
            return Ok(());
        }

        let (state, exec_path) = utils::get_container_info(self.id, self.pid)?;
        self.status = CStatus::Running(state);
        self.exec_path = exec_path;

        Ok(())
    }

    pub fn is_running(&self) -> bool {
        matches!(self.status, CStatus::Running(_))
    }
}

fn create_child(fork_args: &ForkArgs) -> Result<Pid> {
    #[cfg(feature = "interactive")]
    let pseudo = {
        let pseudo = pty::openpty(None, None)?;
        fcntl::fcntl(pseudo.master, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        fcntl::fcntl(pseudo.slave, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        pseudo
    };

    let (prdfd, cwrfd) = unistd::pipe2(OFlag::O_CLOEXEC)?;
    let (crdfd, pwrfd) = unistd::pipe2(OFlag::O_CLOEXEC)?;
    match unsafe { unistd::fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            defer! {
                let _ = unistd::close(prdfd);
                let _ = unistd::close(pwrfd);

                if let Some(stdin) = fork_args.stdin {
                    let _ = unistd::close(stdin);
                }
                if let Some(stdout) = fork_args.stdout {
                    let _ = unistd::close(stdout);
                }
                if let Some(stderr) = fork_args.stderr {
                    let _ = unistd::close(stderr);
                }
            }
            unistd::close(crdfd)?;
            unistd::close(cwrfd)?;

            let child_pid = {
                let mut buf: [u8; mem::size_of::<i32>()] = Default::default();
                unistd::read(prdfd, &mut buf)?;
                i32::from_be_bytes(buf)
            };

            wait::waitpid(child, None)?;

            if fork_args.child_pid.is_none() {
                let buf: &mut [u8] = &mut [0];
                unistd::read(prdfd, buf)?;

                let mut contents = String::new();
                if let Some(config_args) = fork_args.config_args.as_ref() {
                    for (key, value) in config_args.uids.iter() {
                        contents.push_str(format!("{} {} 1\n", key, value).as_str())
                    }
                    contents.truncate(contents.len() - 1);
                } else {
                    contents.push_str(format!("0 {} 1", fork_args.container_id).as_str());
                }
                fs::write(format!("/proc/{}/uid_map", child_pid), contents.as_str())?;
                fs::write(format!("/proc/{}/gid_map", child_pid), contents.as_str())?;

                unistd::write(pwrfd, &[0])?;
            }

            let mut buf: [u8; mem::size_of::<i32>()] = Default::default();
            if unistd::read(prdfd, &mut buf)? != 0 {
                let errno = i32::from_be_bytes(buf);
                return Err(anyhow!(
                    utils::ERR_RPC_SYSTEM_ERROR.replace("{}", format!("{}", errno).as_str())
                ));
            }

            #[cfg(feature = "interactive")]
            {
                unistd::close(pseudo.slave)?;
                tokio::spawn(tdpty::monitor_terminal(pseudo.master));
            }

            Ok(Pid::from_raw(child_pid))
        }
        Ok(ForkResult::Child) => {
            #[cfg(not(feature = "interactive"))]
            let pid = run_child(fork_args, None, cwrfd, crdfd)?;
            #[cfg(feature = "interactive")]
            let pid = run_child(fork_args, Some(pseudo.slave), cwrfd, crdfd)?;

            unistd::write(cwrfd, &i32::from(pid).to_be_bytes())?;
            process::exit(0);
        }
        Err(errno) => Err(anyhow!(
            utils::ERR_RPC_SYSTEM_ERROR.replace("{}", format!("{}", errno).as_str())
        )),
    }
}

fn run_child(fork_args: &ForkArgs, slave: Option<i32>, cwrfd: i32, crdfd: i32) -> Result<Pid> {
    if let Some(stdin) = fork_args.stdin {
        unistd::dup2(stdin, libc::STDIN_FILENO)?;
    }
    if let Some(stdout) = fork_args.stdout {
        unistd::dup2(stdout, libc::STDOUT_FILENO)?;
    }
    if let Some(stderr) = fork_args.stderr {
        unistd::dup2(stderr, libc::STDERR_FILENO)?;
    }

    let gid = Gid::from_raw(fork_args.container_id);
    let uid = Uid::from_raw(fork_args.container_id);
    let rootfs = utils::get_rootfs_path(fork_args.container_id);

    if let Some(pid) = fork_args.child_pid {
        unistd::setresgid(gid, gid, gid)?;
        unistd::setresuid(uid, uid, uid)?;

        let nses = vec![
            (format!("/proc/{}/ns/user", pid), CloneFlags::CLONE_NEWUSER),
            (format!("/proc/{}/ns/mnt", pid), CloneFlags::CLONE_NEWNS),
            (format!("/proc/{}/ns/pid", pid), CloneFlags::CLONE_NEWPID),
            (format!("/proc/{}/ns/ipc", pid), CloneFlags::CLONE_NEWIPC),
        ];

        for ns in nses {
            let fd = fcntl::open(Path::new(&ns.0), OFlag::O_CLOEXEC, Mode::empty())?;
            sched::setns(fd, ns.1)?;
            unistd::close(fd)?;
        }
    } else {
        let config_args = fork_args.config_args.as_ref().unwrap();

        mount::mount(
            None::<&str>,
            &rootfs,
            Some("overlay"),
            MsFlags::empty(),
            Some(config_args.overlay_fs.as_str()),
        )?;

        unistd::chdir(&rootfs)?;
        for (key, value) in config_args.uids.iter() {
            let path = Path::new("run/user").join(format!("{}", key));
            fs::create_dir_all(&path)?;
            unistd::chown(
                &path,
                Some(Uid::from_raw(*value)),
                Some(Gid::from_raw(*value)),
            )?;
        }

        if config_args.writable_fs {
            for entry in walkdir::WalkDir::new("./") {
                let path = entry?.into_path();
                if let Err(errno) = unistd::chown(&path, Some(uid), Some(gid)) {
                    if errno == Errno::EPERM || errno == Errno::ENOENT {
                        continue;
                    }
                }
            }
        }

        unistd::setresgid(gid, gid, gid)?;
        unistd::setresuid(uid, uid, uid)?;

        sched::unshare(
            CloneFlags::CLONE_NEWUSER
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWPID,
        )?;
    }

    match unsafe { unistd::fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            return Ok(child);
        }
        Ok(ForkResult::Child) => (),
        Err(errno) => {
            return Err(anyhow!(
                utils::ERR_RPC_SYSTEM_ERROR.replace("{}", format!("{}", errno).as_str())
            ));
        }
    }

    if fork_args.child_pid.is_none() {
        unistd::write(cwrfd, &[0])?;
        let buf: &mut [u8] = &mut [0];
        unistd::read(crdfd, buf)?;

        for m in ROOTFS_MOUNTS.iter() {
            mount::mount(m.source, m.target, m.fstype, m.flags, m.option)?;
        }
    }

    unistd::chroot(&rootfs)?;
    if let Some(config_args) = fork_args.config_args.as_ref() {
        if let Err(errno) = unistd::chdir(config_args.work_dir.as_str()) {
            if errno == Errno::ENOENT {
                unistd::chdir("/")?;
            }
        }
    } else {
        unistd::chdir("/")?;
    }

    if let Some(fd) = slave {
        unsafe {
            libc::login_tty(fd);
        }
    }

    exec_child(&fork_args.exec_args, cwrfd);
}

fn exec_child(exec_args: &ExecArgs, cwrfd: i32) -> ! {
    let args = exec_args
        .args
        .iter()
        .map(|arg| arg.as_str())
        .collect::<Vec<_>>();

    let cpath = CString::new(args[0]).unwrap_or_default();

    let cargs = args
        .iter()
        .map(|s| CString::new(*s).unwrap_or_default())
        .collect::<Vec<_>>();
    let rcargs = cargs.iter().map(|s| s.as_c_str()).collect::<Vec<_>>();

    for (key, _) in env::vars_os() {
        env::remove_var(key);
    }
    for e in exec_args.envs.iter() {
        if let Some((key, value)) = e.split_once('=') {
            env::set_var(key, value);
        }
    }

    let _ = unistd::execvp(cpath.as_c_str(), rcargs.as_slice()).map_err(|err| {
        let errno = err as i32;
        let _ = unistd::write(cwrfd, &errno.to_be_bytes());
        process::exit(errno);
    });

    unreachable!()
}

#[cfg(not(feature = "interactive"))]
async fn poll_output(
    stdin: RawFd,
    stdout: RawFd,
    stderr: RawFd,
    in_buf: &[u8],
    timeout: u64,
    capture_size: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut in_writer = unsafe { File::from_raw_fd(stdin) };
    let mut out_reader = unsafe { File::from_raw_fd(stdout) };
    let mut err_reader = unsafe { File::from_raw_fd(stderr) };

    let mut out_buf: Vec<u8> = vec![];
    let mut err_buf: Vec<u8> = vec![];
    let mut out_exit = false;
    let mut err_exit = false;

    io::copy(&mut &in_buf[..], &mut in_writer).await?;
    loop {
        tokio::select! {
            _ = time::sleep(Duration::from_secs(timeout)) => {
                tokio::spawn(reclaim_output(out_reader, err_reader));
                break;
            }
            _ = io::copy(&mut out_reader, &mut out_buf) => {
                out_exit = true;
                if out_exit && err_exit {
                    break;
                }
            }
            _ = io::copy(&mut err_reader, &mut err_buf) => {
                err_exit = true;
                if out_exit && err_exit {
                    break;
                }
            }
        }
    }

    if out_buf.len() > capture_size {
        out_buf.drain(0..out_buf.len() - capture_size);
    }

    if err_buf.len() > capture_size {
        err_buf.drain(0..err_buf.len() - capture_size);
    }

    Ok((out_buf, err_buf))
}

#[cfg(not(feature = "interactive"))]
async fn reclaim_output(mut out_reader: File, mut err_reader: File) -> Result<()> {
    let mut out_buf: Vec<u8> = vec![];
    let mut err_buf: Vec<u8> = vec![];
    let mut out_exit = false;
    let mut err_exit = false;

    loop {
        tokio::select! {
            _ = io::copy(&mut out_reader, &mut out_buf) => {
                out_exit = true;
                if out_exit && err_exit {
                    return Ok(());
                }
            }
            _ = io::copy(&mut err_reader, &mut err_buf) => {
                err_exit = true;
                if out_exit && err_exit {
                    return Ok(());
                }
            }
        }
    }
}

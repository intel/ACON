// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

mod grpc {
    tonic::include_proto!("acon.grpc");
}

use anyhow::{anyhow, Result};
use futures::future;
use grpc::{
    AddBlobRequest, AddManifestRequest, AddManifestResponse, ContainerInfo, ExecRequest,
    ExecResponse, GetManifestRequest, GetManifestResponse, InspectRequest, InspectResponse,
    KillRequest, MrLog, ReportRequest, ReportResponse, RestartRequest, StartRequest, StartResponse,
};
use nix::{
    errno::Errno,
    sys::{
        mman::{self, MapFlags, ProtFlags},
        wait,
    },
    unistd::{self, Pid},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap, convert::TryInto, fs::File, mem, num::NonZeroUsize,
    os::unix::io::FromRawFd, os::unix::net::UnixStream as StdUnixStream, slice, str, sync::Arc,
};
use tokio::{
    net::UnixStream,
    signal::unix as tokio_unix,
    sync::{mpsc, watch, RwLock},
    task::JoinHandle,
    time::{self, Duration},
};
use tokio_send_fd::SendFd;

#[cfg(feature = "interactive")]
use crate::pty;
use crate::{
    config::Config,
    container::{self, CStatus, Container},
    image::{Image, Manifest},
    io as acond_io, ipc,
    pod::Pod,
    report, utils,
};

const ACOND_SOCK_PATH: &str = "/shared/acon.sock";

pub async fn start_server(
    stream: StdUnixStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
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
        res = start_service(pod.clone(), UnixStream::from_std(stream)?) => return res,
    }

    shutdown_sender.send(true)?;

    future::join_all(tasks).await;

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

async fn start_service(
    pod: Arc<RwLock<Pod>>,
    mut stream: UnixStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let service = AconService { pod };

    loop {
        let len_buf = acond_io::read_async_with_size(&mut stream, mem::size_of::<u32>()).await?;
        if len_buf.len() != mem::size_of::<u32>() {
            eprintln!(
                "The length of message header is incorrect. {} != 4",
                len_buf.len()
            );
            continue;
        }
        let len_arry = len_buf.try_into().unwrap();
        let len = u32::from_ne_bytes(len_arry) as usize;
        let recv_buf = acond_io::read_async_with_size(&mut stream, len).await?;
        if recv_buf.len() != len {
            eprintln!(
                "The length of message body is incorrect. {} != {}",
                recv_buf.len(),
                len
            );
            continue;
        }

        let send_buf = match recv_buf.is_empty() {
            true => format_error(AcondError::unknown(utils::ERR_UNEXPECTED)),
            false => match invoke_rpc(&service, recv_buf, &stream).await {
                Ok(data) => format_response(data),
                Err(err) => format_error(err),
            },
        };

        acond_io::write_async(&mut stream, &send_buf, send_buf.len()).await?;
    }
}

async fn invoke_rpc(
    service: &AconService,
    request_buf: Vec<u8>,
    stream: &UnixStream,
) -> Result<Vec<u8>, AcondError> {
    match request_buf[0] {
        1 => {
            let request = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            let response = service.add_manifest(&request).await?;
            bincode::serialize(&response).map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))
        }
        2 => {
            service.finalize().await?;
            Ok(vec![0; 0])
        }
        3 => {
            let fd = stream
                .recv_fd()
                .await
                .map_err(|e| AcondError::unknown(e.to_string()))?;

            let file = unsafe { File::from_raw_fd(fd) };
            let len = file
                .metadata()
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?
                .len() as usize;
            let data_addr = unsafe {
                mman::mmap(
                    None,
                    NonZeroUsize::new(len).unwrap(),
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_PRIVATE,
                    fd,
                    0,
                )
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?
            };

            let mut request: AddBlobRequest = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            request.data = unsafe { slice::from_raw_parts(data_addr as *const u8, len).to_vec() };

            unsafe {
                mman::munmap(data_addr, len)
                    .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?
            };
            unistd::close(fd).map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;

            service.add_blob(&request).await?;

            Ok(vec![0; 0])
        }
        4 => {
            let request = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            let response = service.start(&request).await?;
            bincode::serialize(&response).map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))
        }
        5 => {
            let request = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            service.restart(&request).await?;
            Ok(vec![0; 0])
        }
        6 => {
            let request = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            let response = service.exec(&request).await?;
            bincode::serialize(&response).map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))
        }
        7 => {
            let request = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            service.kill(&request).await?;
            Ok(vec![0; 0])
        }
        8 => {
            let request = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            let response = service.inspect(&request).await?;
            bincode::serialize(&response).map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))
        }
        9 => {
            let request = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            let response = service.report(&request).await?;
            bincode::serialize(&response).map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))
        }
        10 => {
            let request = bincode::deserialize(&request_buf[1..])
                .map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))?;
            let response = service.get_manifest(&request).await?;
            bincode::serialize(&response).map_err(|_| AcondError::unknown(utils::ERR_UNEXPECTED))
        }
        _ => Err(AcondError::unknown(utils::ERR_IPC_NOT_SUPPORTED)),
    }
}

fn format_response(mut data: Vec<u8>) -> Vec<u8> {
    data.insert(0, 0);
    data
}

fn format_error(err: AcondError) -> Vec<u8> {
    let mut error = match bincode::serialize(&err) {
        Ok(v) => v,
        Err(_) => {
            let mut v = vec![0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
            v.append(&mut utils::ERR_UNEXPECTED.as_bytes().to_vec());
            v
        }
    };
    error.insert(0, 1);
    error
}

struct AconService {
    pod: Arc<RwLock<Pod>>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    Unknown = 1,
    InvalidArgument = 2,
    DeadlineExceeded = 3,
    PermissionDenied = 4,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AcondError {
    pub code: Code,
    pub message: String,
}

impl AcondError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        AcondError {
            code,
            message: message.into(),
        }
    }

    pub fn unknown(message: impl Into<String>) -> Self {
        AcondError::new(Code::Unknown, message)
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        AcondError::new(Code::InvalidArgument, message)
    }

    pub fn deadline_exceeded(message: impl Into<String>) -> Self {
        AcondError::new(Code::DeadlineExceeded, message)
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        AcondError::new(Code::PermissionDenied, message)
    }
}

impl AconService {
    async fn add_manifest(
        &self,
        request: &AddManifestRequest,
    ) -> Result<AddManifestResponse, AcondError> {
        let manifest_bytes = request.manifest.as_bytes();
        let signature_bytes = request.signature.as_slice();
        let signer_bytes = request.certificate.as_slice();

        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;

        if pod.finalized {
            return Err(AcondError::permission_denied(
                utils::ERR_RPC_MANIFEST_FINALIZED,
            ));
        }

        let verified = utils::verify_signature(manifest_bytes, signature_bytes, signer_bytes)
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        if !verified {
            return Err(AcondError::invalid_argument(
                utils::ERR_RPC_INVALID_SIGNATURE,
            ));
        }

        // verify contents of manifest.
        // ex. layers can't be duplicated.
        // entrypoint mustn't be empty.

        let (hash_algorithm, signer_digest) = utils::calc_certificate_digest(signer_bytes)
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        let (image_id, manifest_digest) =
            utils::calc_image_digest(&hash_algorithm, &signer_digest, manifest_bytes)
                .map_err(|e| AcondError::unknown(e.to_string()))?;

        let manifest: Manifest = serde_json::from_slice(manifest_bytes)
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        let missing_layers = utils::get_missing_layers(&image_id, &manifest.layers)
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        if pod.get_image(&image_id).is_some() {
            return Ok(AddManifestResponse {
                image_id,
                missing_layers,
            });
        }

        let image = Image {
            id: image_id.clone(),
            hash_algorithm,
            signer_digest,
            signer_bytes: signer_bytes.to_vec(),
            manifest_digest,
            manifest,
        };

        let is_accepted = pod
            .is_manifest_accepted(&image)
            .map_err(|e| AcondError::unknown(e.to_string()))?;
        if !is_accepted {
            return Err(AcondError::permission_denied(
                utils::ERR_RPC_INCOMPATIBLE_POLICY,
            ));
        }

        utils::create_alias_link(&image).map_err(|e| AcondError::unknown(e.to_string()))?;

        utils::measure_image(Some(&image_id)).map_err(|e| AcondError::unknown(e.to_string()))?;

        utils::setup_image_dtree(&image, manifest_bytes)
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        pod.add_image(image);

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(AddManifestResponse {
            image_id,
            missing_layers,
        })
    }

    async fn finalize(&self) -> Result<(), AcondError> {
        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;

        if pod.finalized {
            return Err(AcondError::permission_denied(
                utils::ERR_RPC_MANIFEST_FINALIZED,
            ));
        }

        utils::measure_image(None).map_err(|e| AcondError::unknown(e.to_string()))?;

        pod.finalized = true;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(())
    }

    async fn add_blob(&self, request: &AddBlobRequest) -> Result<(), AcondError> {
        let layers = utils::calc_blob_digest(request.alg, &request.data)
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        if !pod.is_blob_accepted(&layers) {
            return Err(AcondError::permission_denied(utils::ERR_RPC_REJECT_BLOB));
        }

        utils::save_blob(&layers, &request.data).map_err(|e| AcondError::unknown(e.to_string()))?;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(())
    }

    async fn start(&self, request: &StartRequest) -> Result<StartResponse, AcondError> {
        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;
        let image = pod
            .get_image(&request.image_id)
            .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?;

        let container = Container::start(image, &request.envs)
            .await
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        let response = StartResponse {
            container_id: container.id,
        };

        pod.add_container(container);

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(response)
    }

    async fn restart(&self, request: &RestartRequest) -> Result<(), AcondError> {
        let container_id = request.container_id;
        let timeout = request.timeout;

        let exit_notifier = {
            let ref_pod = self.pod.clone();
            let pod = ref_pod.read().await;
            let container = pod
                .get_container(&container_id)
                .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;
            let image = pod
                .get_image(&container.image_id)
                .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?;

            if image.manifest.no_restart {
                return Err(AcondError::permission_denied(
                    utils::ERR_RPC_CONTAINER_NOT_ALLOW_RESTART,
                ));
            }

            if container.is_running() {
                if timeout == 0 {
                    return Err(AcondError::deadline_exceeded(
                        utils::ERR_RPC_CONTAINER_RESTART_TIMEOUT,
                    ));
                }

                let sig = if !image.manifest.signals.is_empty() {
                    let s = image.manifest.signals[0];
                    if s.abs() == libc::SIGTERM || s.abs() == libc::SIGKILL {
                        s
                    } else {
                        return Err(AcondError::permission_denied(
                            utils::ERR_RPC_CONTAINER_NOT_ALLOW_RESTART,
                        ));
                    }
                } else {
                    return Err(AcondError::permission_denied(
                        utils::ERR_RPC_CONTAINER_NOT_ALLOW_RESTART,
                    ));
                };

                unsafe {
                    let mut pid: i32 = container.pid.into();
                    if sig < 0 {
                        pid = -pid.abs();
                    }

                    Errno::result(libc::kill(pid, sig.abs())).map_err(|errno| {
                        AcondError::unknown(
                            utils::ERR_RPC_SYSTEM_ERROR
                                .replace("{}", format!("{}", errno).as_str()),
                        )
                    })?;
                }

                Some(container.exit_notifier.as_ref().unwrap().clone())
            } else {
                None
            }
        };

        if let Some(notifier) = exit_notifier {
            loop {
                tokio::select! {
                    _ = time::sleep(Duration::from_secs(timeout)) => {
                        return Err(AcondError::deadline_exceeded(
                            utils::ERR_RPC_CONTAINER_RESTART_TIMEOUT,
                        ));
                    }
                    _ = notifier.notified() => break,
                }
            }
        }

        let image = {
            let ref_pod = self.pod.clone();
            let pod = ref_pod.read().await;
            let container = pod
                .get_container(&container_id)
                .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;
            pod.get_image(&container.image_id)
                .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?
                .clone()
        };

        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;
        let container = pod
            .get_container_mut(&container_id)
            .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;
        container
            .restart(&image)
            .await
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(())
    }

    async fn exec(&self, request: &ExecRequest) -> Result<ExecResponse, AcondError> {
        let container_id = request.container_id;
        let command = request.command.as_str();
        let arguments = &request.arguments;
        let envs = &request.envs;
        let timeout = request.timeout;
        let stdin = request.stdin.as_slice();
        let mut capture_size = request.capture_size as usize;

        if capture_size == 0 {
            capture_size = container::MAX_BUFF_LEN;
        }

        if stdin.len() > capture_size {
            return Err(AcondError::invalid_argument(utils::ERR_RPC_BUFFER_EXCEED));
        }

        if !utils::start_with_uppercase(command) {
            return Err(AcondError::invalid_argument(
                utils::ERR_RPC_PRIVATE_ENTRYPOINT,
            ));
        }

        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        let container = pod
            .get_container(&container_id)
            .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;

        if !container.is_running() {
            return Err(AcondError::unknown(utils::ERR_RPC_CONTAINER_TERMINATED));
        }

        let (stdout, stderr) = container
            .enter(command, arguments, envs, timeout, stdin, capture_size)
            .await
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(ExecResponse { stdout, stderr })
    }

    async fn kill(&self, request: &KillRequest) -> Result<(), AcondError> {
        let container_id = request.container_id;
        let signal_num = request.signal_num;

        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        let container = pod
            .get_container(&container_id)
            .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;

        if !container.is_running() {
            return Err(AcondError::unknown(utils::ERR_RPC_CONTAINER_TERMINATED));
        }

        let image = pod
            .get_image(&container.image_id)
            .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?;

        if !image.manifest.signals.iter().any(|&s| s == signal_num) {
            return Err(AcondError::permission_denied(
                utils::ERR_RPC_CONTAINER_NOT_ALLOW_KILL,
            ));
        }

        unsafe {
            let mut pid: i32 = container.pid.into();
            if signal_num < 0 {
                pid = -pid.abs();
            }

            Errno::result(libc::kill(pid, signal_num.abs())).map_err(|errno| {
                AcondError::unknown(
                    utils::ERR_RPC_SYSTEM_ERROR.replace("{}", format!("{}", errno).as_str()),
                )
            })?;
        }

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(())
    }

    async fn inspect(&self, request: &InspectRequest) -> Result<InspectResponse, AcondError> {
        let container_id = request.container_id;

        let mut infos: Vec<ContainerInfo> = vec![];

        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;

        if container_id == 0 {
            for (_, c) in pod.containers.iter_mut() {
                c.update_status()
                    .map_err(|e| AcondError::unknown(e.to_string()))?;

                infos.push(ContainerInfo {
                    container_id: c.id,
                    state: match c.status {
                        CStatus::Running(s) => s,
                        _ => 0,
                    },
                    wstatus: match c.status {
                        CStatus::Exited(s) => s,
                        _ => 0,
                    },
                    image_id: c.image_id.clone(),
                    exe_path: c.exec_path.clone(),
                });
            }
        } else {
            let container = pod
                .get_container_mut(&container_id)
                .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;

            container
                .update_status()
                .map_err(|e| AcondError::unknown(e.to_string()))?;

            infos.push(ContainerInfo {
                container_id: container.id,
                state: match container.status {
                    CStatus::Running(s) => s,
                    _ => 0,
                },
                wstatus: match container.status {
                    CStatus::Exited(s) => s,
                    _ => 0,
                },
                image_id: container.image_id.clone(),
                exe_path: container.exec_path.clone(),
            });
        }

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(InspectResponse { info: infos })
    }

    async fn report(&self, request: &ReportRequest) -> Result<ReportResponse, AcondError> {
        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        if pod.images.is_empty() {
            return Err(AcondError::unknown(utils::ERR_RPC_NO_IMAGES));
        }

        let nonce_hi = request.nonce_hi;
        let nonce_lo = request.nonce_lo;

        let mut mrlog = HashMap::new();
        mrlog.insert(0, MrLog { logs: vec![] });
        mrlog.insert(1, MrLog { logs: vec![] });
        mrlog.insert(2, MrLog { logs: vec![] });
        mrlog.insert(
            3,
            MrLog {
                logs: utils::get_measurement_rtmr3()
                    .map_err(|e| AcondError::unknown(e.to_string()))?,
            },
        );

        let (requestor_nonce, acond_nonce) = utils::get_nounces(nonce_hi, nonce_lo)
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        let attestation_data = pod
            .get_attestation_data(requestor_nonce, acond_nonce, None)
            .map_err(|e| AcondError::unknown(e.to_string()))?;

        let data = match request.request_type {
            0 => report::get_report(&attestation_data)
                .map_err(|e| AcondError::unknown(e.to_string())),
            1 => {
                report::get_quote(&attestation_data).map_err(|e| AcondError::unknown(e.to_string()))
            }
            _ => Err(AcondError::invalid_argument(
                utils::ERR_RPC_INVALID_REQUEST_TYPE,
            )),
        }?;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(ReportResponse {
            data,
            mrlog,
            attestation_data,
        })
    }

    async fn get_manifest(
        &self,
        request: &GetManifestRequest,
    ) -> Result<GetManifestResponse, AcondError> {
        let image_id = &request.image_id;

        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        let image = pod
            .get_image(image_id)
            .ok_or_else(|| AcondError::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?;

        let manifest =
            utils::get_manifest(image_id).map_err(|e| AcondError::unknown(e.to_string()))?;
        let certificate = image.signer_bytes.clone();

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(GetManifestResponse {
            manifest,
            certificate,
        })
    }
}

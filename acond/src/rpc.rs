// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use grpc::acon_service_server::{AconService, AconServiceServer};
use grpc::{
    AddBlobRequest, AddManifestRequest, AddManifestResponse, ContainerInfo, ExecRequest,
    ExecResponse, GetManifestRequest, GetManifestResponse, InspectRequest, InspectResponse,
    KillRequest, MrLog, ReportRequest, ReportResponse, RestartRequest, StartRequest, StartResponse,
};
use nix::errno::Errno;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::RwLock,
    time::{self, Duration},
};
use tokio_vsock::VsockListener;
use tonic::{transport::Server, Request, Response, Status};

use crate::{
    container::{self, CStatus, Container},
    image::{Image, Manifest},
    pod::Pod,
    report, utils, vsock_incoming,
};

mod grpc {
    tonic::include_proto!("acon.grpc");
}

#[derive(Clone)]
struct TDAconService {
    pod: Arc<RwLock<Pod>>,
}

// implementing rpc for service defined in .proto
#[tonic::async_trait]
impl AconService for TDAconService {
    async fn add_manifest(
        &self,
        request: Request<AddManifestRequest>,
    ) -> Result<Response<AddManifestResponse>, Status> {
        let manifest_bytes = request.get_ref().manifest.as_bytes();
        let signature_bytes = request.get_ref().signature.as_slice();
        let signer_bytes = request.get_ref().certificate.as_slice();

        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;

        if pod.finalized {
            return Err(Status::permission_denied(utils::ERR_RPC_MANIFEST_FINALIZED));
        }

        let verified = utils::verify_signature(manifest_bytes, signature_bytes, signer_bytes)
            .map_err(|e| Status::unknown(e.to_string()))?;

        if !verified {
            return Err(Status::invalid_argument(utils::ERR_RPC_INVALID_SIGNATURE));
        }

        // verify contents of manifest.
        // ex. layers can't be duplicated.
        // entrypoint mustn't be empty.

        let (hash_algorithm, signer_digest) = utils::calc_certificate_digest(signer_bytes)
            .map_err(|e| Status::unknown(e.to_string()))?;

        let (image_id, manifest_digest) =
            utils::calc_image_digest(&hash_algorithm, &signer_digest, manifest_bytes)
                .map_err(|e| Status::unknown(e.to_string()))?;

        let manifest: Manifest =
            serde_json::from_slice(manifest_bytes).map_err(|e| Status::unknown(e.to_string()))?;

        let missing_layers = utils::get_missing_layers(&image_id, &manifest.layers)
            .map_err(|e| Status::unknown(e.to_string()))?;

        if pod.get_image(&image_id).is_some() {
            return Ok(Response::new(AddManifestResponse {
                image_id,
                missing_layers,
            }));
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
            .map_err(|e| Status::unknown(e.to_string()))?;
        if !is_accepted {
            return Err(Status::permission_denied(
                utils::ERR_RPC_INCOMPATIBLE_POLICY,
            ));
        }

        utils::create_alias_link(&image).map_err(|e| Status::unknown(e.to_string()))?;

        utils::measure_image(Some(&image_id)).map_err(|e| Status::unknown(e.to_string()))?;

        utils::setup_image_dtree(&image, manifest_bytes)
            .map_err(|e| Status::unknown(e.to_string()))?;

        pod.add_image(image);

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(AddManifestResponse {
            image_id,
            missing_layers,
        }))
    }

    async fn finalize(&self, _: Request<()>) -> Result<Response<()>, Status> {
        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;

        if pod.finalized {
            return Err(Status::permission_denied(utils::ERR_RPC_MANIFEST_FINALIZED));
        }

        utils::measure_image(None).map_err(|e| Status::unknown(e.to_string()))?;

        pod.finalized = true;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(()))
    }

    async fn add_blob(&self, request: Request<AddBlobRequest>) -> Result<Response<()>, Status> {
        let algorithm = request.get_ref().alg;
        let data = request.get_ref().data.as_slice();

        let layers =
            utils::calc_blob_digest(algorithm, data).map_err(|e| Status::unknown(e.to_string()))?;

        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        if !pod.is_blob_accepted(&layers) {
            return Err(Status::permission_denied(utils::ERR_RPC_REJECT_BLOB));
        }

        utils::save_blob(&layers, data).map_err(|e| Status::unknown(e.to_string()))?;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(()))
    }

    async fn start(
        &self,
        request: Request<StartRequest>,
    ) -> Result<Response<StartResponse>, Status> {
        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;
        let image = pod
            .get_image(&request.get_ref().image_id)
            .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?;

        let container = Container::start(image, &request.get_ref().envs)
            .await
            .map_err(|e| Status::unknown(e.to_string()))?;

        let response = StartResponse {
            container_id: container.id,
        };

        pod.add_container(container);

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(response))
    }

    async fn restart(&self, request: Request<RestartRequest>) -> Result<Response<()>, Status> {
        let container_id = request.get_ref().container_id;
        let timeout = request.get_ref().timeout;

        let exit_notifier = {
            let ref_pod = self.pod.clone();
            let pod = ref_pod.read().await;
            let container = pod
                .get_container(&container_id)
                .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;
            let image = pod
                .get_image(&container.image_id)
                .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?;

            if image.manifest.no_restart {
                return Err(Status::permission_denied(
                    utils::ERR_RPC_CONTAINER_NOT_ALLOW_RESTART,
                ));
            }

            if container.is_running() {
                if timeout == 0 {
                    return Err(Status::deadline_exceeded(
                        utils::ERR_RPC_CONTAINER_RESTART_TIMEOUT,
                    ));
                }

                let sig = if !image.manifest.signals.is_empty() {
                    let s = image.manifest.signals[0];
                    if s.abs() == libc::SIGTERM || s.abs() == libc::SIGKILL {
                        s
                    } else {
                        return Err(Status::permission_denied(
                            utils::ERR_RPC_CONTAINER_NOT_ALLOW_RESTART,
                        ));
                    }
                } else {
                    return Err(Status::permission_denied(
                        utils::ERR_RPC_CONTAINER_NOT_ALLOW_RESTART,
                    ));
                };

                unsafe {
                    let mut pid: i32 = container.pid.into();
                    if sig < 0 {
                        pid = -pid.abs();
                    }

                    Errno::result(libc::kill(pid, sig.abs())).map_err(|errno| {
                        Status::unknown(
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
                        return Err(Status::deadline_exceeded(
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
                .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;
            pod.get_image(&container.image_id)
                .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?
                .clone()
        };

        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;
        let container = pod
            .get_container_mut(&container_id)
            .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;
        container
            .restart(&image)
            .await
            .map_err(|e| Status::unknown(e.to_string()))?;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(()))
    }

    async fn exec(&self, request: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
        let container_id = request.get_ref().container_id;
        let command = request.get_ref().command.as_str();
        let arguments = &request.get_ref().arguments;
        let envs = &request.get_ref().envs;
        let timeout = request.get_ref().timeout;
        let stdin = request.get_ref().stdin.as_slice();
        let mut capture_size = request.get_ref().capture_size as usize;

        if capture_size == 0 {
            capture_size = container::MAX_BUFF_LEN;
        }

        if stdin.len() > capture_size {
            return Err(Status::invalid_argument(utils::ERR_RPC_BUFFER_EXCEED));
        }

        if !utils::start_with_uppercase(command) {
            return Err(Status::invalid_argument(utils::ERR_RPC_PRIVATE_ENTRYPOINT));
        }

        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        let container = pod
            .get_container(&container_id)
            .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;

        if !container.is_running() {
            return Err(Status::unknown(utils::ERR_RPC_CONTAINER_TERMINATED));
        }

        let (stdout, stderr) = container
            .enter(command, arguments, envs, timeout, stdin, capture_size)
            .await
            .map_err(|e| Status::unknown(e.to_string()))?;

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(ExecResponse { stdout, stderr }))
    }

    async fn kill(&self, request: Request<KillRequest>) -> Result<Response<()>, Status> {
        let container_id = request.get_ref().container_id;
        let signal_num = request.get_ref().signal_num;

        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        let container = pod
            .get_container(&container_id)
            .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;

        if !container.is_running() {
            return Err(Status::unknown(utils::ERR_RPC_CONTAINER_TERMINATED));
        }

        let image = pod
            .get_image(&container.image_id)
            .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?;

        if let None = image.manifest.signals.iter().find(|&&s| s == signal_num) {
            return Err(Status::permission_denied(
                utils::ERR_RPC_CONTAINER_NOT_ALLOW_KILL,
            ));
        }

        unsafe {
            let mut pid: i32 = container.pid.into();
            if signal_num < 0 {
                pid = -pid.abs();
            }

            Errno::result(libc::kill(pid, signal_num.abs())).map_err(|errno| {
                Status::unknown(
                    utils::ERR_RPC_SYSTEM_ERROR.replace("{}", format!("{}", errno).as_str()),
                )
            })?;
        }

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(()))
    }

    async fn inspect(
        &self,
        request: Request<InspectRequest>,
    ) -> Result<Response<InspectResponse>, Status> {
        let container_id = request.get_ref().container_id;

        let mut infos: Vec<ContainerInfo> = vec![];

        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;

        if container_id == 0 {
            for (_, c) in pod.containers.iter_mut() {
                c.update_status()
                    .map_err(|e| Status::unknown(e.to_string()))?;

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
                .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_CONTAINER_ID))?;

            container
                .update_status()
                .map_err(|e| Status::unknown(e.to_string()))?;

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

        Ok(Response::new(InspectResponse { info: infos }))
    }

    async fn report(
        &self,
        request: Request<ReportRequest>,
    ) -> Result<Response<ReportResponse>, Status> {
        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        if pod.images.is_empty() {
            return Err(Status::unknown(utils::ERR_RPC_NO_IMAGES));
        }

        let nonce_hi = request.get_ref().nonce_hi;
        let nonce_lo = request.get_ref().nonce_lo;

        let mut mrlog = HashMap::new();
        mrlog.insert(0, MrLog { logs: vec![] });
        mrlog.insert(1, MrLog { logs: vec![] });
        mrlog.insert(2, MrLog { logs: vec![] });
        mrlog.insert(
            3,
            MrLog {
                logs: utils::get_measurement_rtmr3().map_err(|e| Status::unknown(e.to_string()))?,
            },
        );

        let (requestor_nonce, acond_nonce) =
            utils::get_nounces(nonce_hi, nonce_lo).map_err(|e| Status::unknown(e.to_string()))?;

        let attestation_data = pod
            .get_attestation_data(requestor_nonce, acond_nonce, None)
            .map_err(|e| Status::unknown(e.to_string()))?;

        let data =
            match request.get_ref().data_type {
                0 => report::get_report(&attestation_data)
                    .map_err(|e| Status::unknown(e.to_string()))?,
                _ => report::get_quote(&attestation_data)
                    .map_err(|e| Status::unknown(e.to_string()))?,
            };

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(ReportResponse {
            data,
            mrlog,
            attestation_data,
        }))
    }

    async fn get_manifest(
        &self,
        request: Request<GetManifestRequest>,
    ) -> Result<Response<GetManifestResponse>, Status> {
        let image_id = &request.get_ref().image_id;

        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;
        let image = pod
            .get_image(image_id)
            .ok_or_else(|| Status::invalid_argument(utils::ERR_RPC_INVALID_IMAGE_ID))?;

        let manifest = utils::get_manifest(image_id).map_err(|e| Status::unknown(e.to_string()))?;
        let certificate = image.signer_bytes.clone();

        if let Some(tx) = &pod.timeout_tx {
            let _ = tx.send(false).await;
        }

        Ok(Response::new(GetManifestResponse {
            manifest,
            certificate,
        }))
    }
}

pub async fn run_vsock_server(
    pod: Arc<RwLock<Pod>>,
    port: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = VsockListener::bind(libc::VMADDR_CID_ANY, port)?;
    let incoming = vsock_incoming::VsockIncoming::new(listener);

    Server::builder()
        .add_service(AconServiceServer::new(TDAconService { pod }))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

pub async fn run_tcp_server(
    pod: Arc<RwLock<Pod>>,
    port: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = format!("0.0.0.0:{}", port).parse()?;

    Server::builder()
        .add_service(AconServiceServer::new(TDAconService { pod }))
        .serve(server_addr)
        .await?;

    Ok(())
}

// unix socket for testing
pub async fn run_unix_server(
    pod: Arc<RwLock<Pod>>,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let unix_path = std::path::Path::new(path);
    if unix_path.exists() {
        std::fs::remove_file(unix_path)?;
    }
    std::fs::create_dir_all(unix_path.parent().unwrap())?;

    let listener = tokio::net::UnixListener::bind(path)?;
    let incoming = crate::unix_incoming::UnixIncoming::new(listener);

    Server::builder()
        .add_service(AconServiceServer::new(TDAconService { pod }))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

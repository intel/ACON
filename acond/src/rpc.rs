// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

mod grpc {
    tonic::include_proto!("acon.grpc");
}

use anyhow::Result;
use grpc::acon_service_server::{AconService, AconServiceServer};
use grpc::{
    AddBlobRequest, AddManifestRequest, AddManifestResponse, ExecRequest, ExecResponse,
    GetManifestRequest, GetManifestResponse, InspectRequest, InspectResponse, KillRequest,
    ReportRequest, ReportResponse, RestartRequest, StartRequest, StartResponse,
};
use nix::unistd;
use std::{
    io::Write,
    os::unix::{io::AsRawFd, net::UnixStream as StdUnixStream},
    sync::Arc,
};
use tempfile::NamedTempFile;
use tokio::{net::UnixStream, sync::Mutex};
use tokio_send_fd::SendFd;
use tokio_vsock::VsockListener;
use tonic::{transport::Server, Request, Response, Status};

use crate::{
    io as acond_io,
    server::{AcondError, Code},
    utils, vsock_incoming,
};

const DEBUG_SOCK_PATH: &str = "/tmp/acon.sock";

#[derive(Clone)]
struct TDAconService {
    stream: Arc<Mutex<UnixStream>>,
}

impl TDAconService {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
        }
    }

    async fn do_exchange(
        &self,
        command: u8,
        mut buf: Vec<u8>,
        file: Option<&NamedTempFile>,
    ) -> Result<Vec<u8>, Status> {
        buf.insert(0, command);

        let mut send_buf = (buf.len() as u32).to_ne_bytes().to_vec();
        send_buf.append(&mut buf);
        acond_io::write_async_lock(self.stream.clone(), &send_buf, send_buf.len())
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        if let Some(f) = file {
            let ref_stream = self.stream.clone();
            let stream = ref_stream.lock().await;
            stream.send_fd(f.as_raw_fd()).await?;
            unistd::close(f.as_raw_fd()).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
            unistd::unlink(f.path()).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        }

        let recv_buf = acond_io::read_async_lock(self.stream.clone())
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match recv_buf.first() {
            Some(0) => Ok(recv_buf.get(1..).map_or(Vec::new(), |v| v.to_vec())),
            Some(1) => {
                let error: AcondError = bincode::deserialize(recv_buf.get(1..).unwrap_or(&[]))
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                match error.code {
                    Code::Unknown => Err(Status::new(tonic::Code::Unknown, error.message)),
                    Code::InvalidArgument => {
                        Err(Status::new(tonic::Code::InvalidArgument, error.message))
                    }
                    Code::DeadlineExceeded => {
                        Err(Status::new(tonic::Code::DeadlineExceeded, error.message))
                    }
                    Code::PermissionDenied => {
                        Err(Status::new(tonic::Code::PermissionDenied, error.message))
                    }
                }
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }
}

// implementing rpc for service defined in .proto
#[tonic::async_trait]
impl AconService for TDAconService {
    async fn add_manifest(
        &self,
        request: Request<AddManifestRequest>,
    ) -> Result<Response<AddManifestResponse>, Status> {
        let send_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let recv_buf = self.do_exchange(1, send_buf, None).await?;

        Ok(Response::new(
            bincode::deserialize(&recv_buf).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?,
        ))
    }

    async fn finalize(&self, _: Request<()>) -> Result<Response<()>, Status> {
        self.do_exchange(2, vec![0; 0], None).await?;
        Ok(Response::new(()))
    }

    async fn add_blob(&self, request: Request<AddBlobRequest>) -> Result<Response<()>, Status> {
        let mut file = NamedTempFile::new().map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        file.write_all(&request.get_ref().data)
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let send_buf: Vec<u8> = bincode::serialize(&AddBlobRequest {
            alg: request.get_ref().alg,
            data: vec![],
        })
        .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        self.do_exchange(3, send_buf, Some(&file)).await?;

        Ok(Response::new(()))
    }

    async fn start(
        &self,
        request: Request<StartRequest>,
    ) -> Result<Response<StartResponse>, Status> {
        let send_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let recv_buf = self.do_exchange(4, send_buf, None).await?;

        Ok(Response::new(
            bincode::deserialize(&recv_buf).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?,
        ))
    }

    async fn restart(&self, request: Request<RestartRequest>) -> Result<Response<()>, Status> {
        let send_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let recv_buf = self.do_exchange(5, send_buf, None).await?;

        Ok(Response::new(
            bincode::deserialize(&recv_buf).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?,
        ))
    }

    async fn exec(&self, request: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
        let send_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let recv_buf = self.do_exchange(6, send_buf, None).await?;

        Ok(Response::new(
            bincode::deserialize(&recv_buf).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?,
        ))
    }

    async fn kill(&self, request: Request<KillRequest>) -> Result<Response<()>, Status> {
        let send_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        self.do_exchange(7, send_buf, None).await?;

        Ok(Response::new(()))
    }

    async fn inspect(
        &self,
        request: Request<InspectRequest>,
    ) -> Result<Response<InspectResponse>, Status> {
        let send_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let recv_buf = self.do_exchange(8, send_buf, None).await?;

        Ok(Response::new(
            bincode::deserialize(&recv_buf).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?,
        ))
    }

    async fn report(
        &self,
        request: Request<ReportRequest>,
    ) -> Result<Response<ReportResponse>, Status> {
        let send_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let recv_buf = self.do_exchange(9, send_buf, None).await?;

        Ok(Response::new(
            bincode::deserialize(&recv_buf).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?,
        ))
    }

    async fn get_manifest(
        &self,
        request: Request<GetManifestRequest>,
    ) -> Result<Response<GetManifestResponse>, Status> {
        let send_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let recv_buf = self.do_exchange(10, send_buf, None).await?;

        Ok(Response::new(
            bincode::deserialize(&recv_buf).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?,
        ))
    }
}

pub async fn run_vsock_server(
    stream: StdUnixStream,
    port: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = VsockListener::bind(libc::VMADDR_CID_ANY, port)?;
    let incoming = vsock_incoming::VsockIncoming::new(listener);

    Server::builder()
        .add_service(AconServiceServer::new(TDAconService::new(
            UnixStream::from_std(stream)?,
        )))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

pub async fn run_tcp_server(
    stream: StdUnixStream,
    port: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = format!("0.0.0.0:{}", port).parse()?;

    Server::builder()
        .add_service(AconServiceServer::new(TDAconService::new(
            UnixStream::from_std(stream)?,
        )))
        .serve(server_addr)
        .await?;

    Ok(())
}

// unix socket for testing
pub async fn run_unix_server(stream: StdUnixStream) -> Result<(), Box<dyn std::error::Error>> {
    let unix_path = std::path::Path::new(DEBUG_SOCK_PATH);
    if unix_path.exists() {
        std::fs::remove_file(unix_path)?;
    }
    std::fs::create_dir_all(unix_path.parent().unwrap())?;

    let listener = tokio::net::UnixListener::bind(unix_path)?;
    let incoming = crate::unix_incoming::UnixIncoming::new(listener);

    Server::builder()
        .add_service(AconServiceServer::new(TDAconService::new(
            UnixStream::from_std(stream)?,
        )))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

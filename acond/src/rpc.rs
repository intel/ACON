// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

mod grpc {
    tonic::include_proto!("acon.grpc");
}

use anyhow::{anyhow, Result};
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

    async fn send_recv(&self, command: u8, buf: &mut Vec<u8>) -> Result<Vec<u8>> {
        buf.insert(0, command);

        let mut send_buf = (buf.len() as u32).to_ne_bytes().to_vec();
        send_buf.append(buf);
        acond_io::write_async_lock(self.stream.clone(), &send_buf, send_buf.len()).await?;

        let recv_buf = acond_io::read_async_lock(self.stream.clone()).await?;
        if recv_buf.is_empty() {
            return Err(anyhow!(utils::ERR_UNEXPECTED));
        }
        Ok(recv_buf)
    }

    async fn send_recv2(
        &self,
        command: u8,
        buf: &mut Vec<u8>,
        file: &NamedTempFile,
    ) -> Result<Vec<u8>> {
        buf.insert(0, command);

        let mut send_buf = (buf.len() as u32).to_ne_bytes().to_vec();
        send_buf.append(buf);
        acond_io::write_async_lock(self.stream.clone(), &send_buf, send_buf.len()).await?;

        {
            let ref_stream = self.stream.clone();
            let stream = ref_stream.lock().await;
            stream.send_fd(file.as_raw_fd()).await?;
            unistd::close(file.as_raw_fd()).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
            unistd::unlink(file.path()).map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        }

        let recv_buf = acond_io::read_async_lock(self.stream.clone()).await?;
        if recv_buf.is_empty() {
            return Err(anyhow!(utils::ERR_UNEXPECTED));
        }
        Ok(recv_buf)
    }
}

// implementing rpc for service defined in .proto
#[tonic::async_trait]
impl AconService for TDAconService {
    async fn add_manifest(
        &self,
        request: Request<AddManifestRequest>,
    ) -> Result<Response<AddManifestResponse>, Status> {
        let mut request_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv(1, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => {
                let response = bincode::deserialize(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Ok(Response::new(response))
            }
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn finalize(&self, _: Request<()>) -> Result<Response<()>, Status> {
        let mut request_buf: Vec<u8> = vec![0; 0];
        let response_buf = self
            .send_recv(2, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => Ok(Response::new(())),
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn add_blob(&self, request: Request<AddBlobRequest>) -> Result<Response<()>, Status> {
        let mut file = NamedTempFile::new().map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        file.write_all(&request.get_ref().data)
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        let inner_request = AddBlobRequest {
            alg: request.get_ref().alg,
            data: vec![],
        };
        let mut request_buf: Vec<u8> = bincode::serialize(&inner_request)
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv2(3, &mut request_buf, &file)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => Ok(Response::new(())),
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn start(
        &self,
        request: Request<StartRequest>,
    ) -> Result<Response<StartResponse>, Status> {
        let mut request_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv(4, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => {
                let response = bincode::deserialize(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Ok(Response::new(response))
            }
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn restart(&self, request: Request<RestartRequest>) -> Result<Response<()>, Status> {
        let mut request_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv(5, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => Ok(Response::new(())),
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn exec(&self, request: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
        let mut request_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv(6, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => {
                let response = bincode::deserialize(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Ok(Response::new(response))
            }
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn kill(&self, request: Request<KillRequest>) -> Result<Response<()>, Status> {
        let mut request_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv(7, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => Ok(Response::new(())),
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn inspect(
        &self,
        request: Request<InspectRequest>,
    ) -> Result<Response<InspectResponse>, Status> {
        let mut request_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv(8, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => {
                let response = bincode::deserialize(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Ok(Response::new(response))
            }
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn report(
        &self,
        request: Request<ReportRequest>,
    ) -> Result<Response<ReportResponse>, Status> {
        let mut request_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv(9, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => {
                let response = bincode::deserialize(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Ok(Response::new(response))
            }
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }

    async fn get_manifest(
        &self,
        request: Request<GetManifestRequest>,
    ) -> Result<Response<GetManifestResponse>, Status> {
        let mut request_buf: Vec<u8> = bincode::serialize(request.get_ref())
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
        let response_buf = self
            .send_recv(10, &mut request_buf)
            .await
            .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;

        match response_buf[0] {
            0 => {
                let response = bincode::deserialize(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Ok(Response::new(response))
            }
            1 => {
                let status = get_status(&response_buf[1..])
                    .map_err(|_| Status::unknown(utils::ERR_UNEXPECTED))?;
                Err(status)
            }
            _ => Err(Status::unknown(utils::ERR_UNEXPECTED)),
        }
    }
}

fn get_status(buf: &[u8]) -> Result<Status> {
    let error: AcondError = bincode::deserialize(buf)?;
    let code = match error.code {
        Code::Unknown => tonic::Code::Unknown,
        Code::InvalidArgument => tonic::Code::InvalidArgument,
        Code::DeadlineExceeded => tonic::Code::DeadlineExceeded,
        Code::PermissionDenied => tonic::Code::PermissionDenied,
    };
    Ok(Status::new(code, error.message))
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

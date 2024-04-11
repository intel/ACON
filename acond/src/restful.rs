// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    io as acond_io,
    server::{
        AcondError, AddBlobRequest, AddManifestRequest, AddManifestResponse, Code, ExecRequest,
        ExecResponse, GetManifestRequest, GetManifestResponse, InspectRequest, InspectResponse,
        KillRequest, ReportRequest, ReportResponse, RestartRequest, StartRequest, StartResponse,
    },
    utils,
};
use actix_web::{
    http::{self, StatusCode},
    web, App, HttpResponse, HttpServer, ResponseError,
};
use anyhow::{anyhow, Result};
use futures::{StreamExt, TryStreamExt};
use nix::{
    fcntl::{self, FlockArg},
    unistd,
};
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
    x509::{extension::BasicConstraints, X509Builder, X509NameBuilder},
};
use serde::Deserialize;
use std::{
    fmt,
    io::SeekFrom,
    os::{fd::AsRawFd, unix::net::UnixStream as StdUnixStream},
    path::Path,
    sync::Arc,
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncSeekExt, AsyncWriteExt},
    net::UnixStream,
    sync::Mutex,
};
use tokio_send_fd::SendFd;

#[derive(Debug)]
enum RestError {
    Unknown(String),
    InvalidArgument(String),
    DeadlineExceeded(String),
    PermissionDenied(String),
}

impl fmt::Display for RestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RestError::Unknown(error) => write!(f, "{}", error),
            RestError::InvalidArgument(error) => write!(f, "{}", error),
            RestError::DeadlineExceeded(error) => write!(f, "{}", error),
            RestError::PermissionDenied(error) => write!(f, "{}", error),
        }
    }
}

impl std::error::Error for RestError {}

impl ResponseError for RestError {
    fn status_code(&self) -> StatusCode {
        match *self {
            RestError::Unknown(_) => StatusCode::INTERNAL_SERVER_ERROR,
            RestError::InvalidArgument(_) => StatusCode::BAD_REQUEST,
            RestError::DeadlineExceeded(_) => StatusCode::REQUEST_TIMEOUT,
            RestError::PermissionDenied(_) => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let error_message = format!("{}", self);
        HttpResponse::build(self.status_code()).body(error_message)
    }
}

async fn add_manifest(
    mut payload: actix_multipart::Multipart,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut request = AddManifestRequest::default();

    while let Ok(Some(mut field)) = payload.try_next().await {
        let mut data = vec![];
        while let Some(chunk) = field.next().await {
            data.append(
                &mut chunk
                    .map_err(|e| RestError::Unknown(e.to_string()))?
                    .to_vec(),
            );
        }

        match field.name() {
            "manifest" => request.manifest = data,
            "sig" => request.signature = data,
            "cert" => request.certificate = data,
            _ => continue,
        }
    }

    let mut request_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;
    let response_buf = service
        .send_recv(1, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => {
            let response: AddManifestResponse = bincode::deserialize(&response_buf[1..])
                .map_err(|e| RestError::Unknown(e.to_string()))?;
            Ok(HttpResponse::Ok().json(response))
        }
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

async fn finalize(service: web::Data<ExchangeService>) -> Result<HttpResponse, RestError> {
    let mut request_buf: Vec<u8> = vec![0; 0];
    let response_buf = service
        .send_recv(2, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => Ok(HttpResponse::Ok().finish()),
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

async fn get_manifest(
    path: web::Path<(String, String, String)>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let request = GetManifestRequest {
        image_id: format!("{}/{}/{}", path.0, path.1, path.2),
    };
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;
    let response_buf = service
        .send_recv(10, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => {
            let response: GetManifestResponse = bincode::deserialize(&response_buf[1..])
                .map_err(|e| RestError::Unknown(e.to_string()))?;
            Ok(HttpResponse::Ok().json(response))
        }
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

#[derive(Deserialize)]
struct AddBlobQueryParam {
    alg: u32,
}

async fn add_blob(
    blob_name: web::Path<String>,
    query_param: web::Query<AddBlobQueryParam>,
    range: Option<web::Header<http::header::ContentRange>>,
    mut payload: web::Payload,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let blob_name = format!("/run/user/1/{}", *blob_name);
    let blob_path = Path::new(blob_name.as_str());

    let mut start = 0;
    if let Some(ref range) = range {
        start = utils::extract_start(range).unwrap_or(0);
    }

    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .open(blob_path)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    fcntl::flock(f.as_raw_fd(), FlockArg::LockSharedNonblock)
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    let metadata = f
        .metadata()
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    if start > metadata.len() {
        return Err(RestError::InvalidArgument(
            "The start of content range parameter is bigger than the existing file.".into(),
        ));
    }
    fcntl::flock(f.as_raw_fd(), FlockArg::UnlockNonblock)
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    fcntl::flock(f.as_raw_fd(), FlockArg::LockExclusiveNonblock)
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    while let Some(chunk) = payload.next().await {
        let data = chunk.map_err(|e| RestError::Unknown(e.to_string()))?;

        f.seek(SeekFrom::Start(start))
            .await
            .map_err(|e| RestError::Unknown(e.to_string()))?;
        f.write_all(&data)
            .await
            .map_err(|e| RestError::Unknown(e.to_string()))?;

        start += data.len() as u64;
    }

    let request = AddBlobRequest {
        alg: query_param.alg,
        data: vec![],
    };
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;
    let response_buf = service
        .send_recv2(3, &mut request_buf, blob_path)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => Ok(HttpResponse::Ok().finish()),
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

async fn get_blob_size(blob_name: web::Path<String>) -> Result<HttpResponse, RestError> {
    let blob_name = format!("/run/user/1/{}", *blob_name);
    let blob_path = Path::new(blob_name.as_str());

    let mut blob_size = 0;
    if blob_path.exists() {
        let metadata = blob_path
            .metadata()
            .map_err(|e| RestError::Unknown(e.to_string()))?;
        blob_size = metadata.len()
    }

    Ok(HttpResponse::Ok().json(blob_size))
}

#[derive(Deserialize)]
struct StartQueryParam {
    image_id: String,
}

async fn start(
    query_param: web::Query<StartQueryParam>,
    mut payload: actix_multipart::Multipart,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut envs = Vec::new();
    while let Ok(Some(mut field)) = payload.try_next().await {
        let mut data = vec![];
        while let Some(chunk) = field.next().await {
            data.append(
                &mut chunk
                    .map_err(|e| RestError::Unknown(e.to_string()))?
                    .to_vec(),
            );
        }
        match field.name() {
            "env" => {
                let mut v = String::from_utf8(data)
                    .unwrap_or_default()
                    .split('\n')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                envs.append(&mut v);
            }
            _ => continue,
        }
    }

    let request = StartRequest {
        image_id: query_param.image_id.clone(),
        envs,
    };
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    let response_buf = service
        .send_recv(4, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => {
            let response: StartResponse = bincode::deserialize(&response_buf[1..])
                .map_err(|e| RestError::Unknown(e.to_string()))?;
            Ok(HttpResponse::Ok().json(response))
        }
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

#[derive(Deserialize)]
struct RestartFormParam {
    #[serde(default)]
    timeout: u64,
}

async fn restart(
    form_param: web::Form<RestartFormParam>,
    container_id: web::Path<u32>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let request = RestartRequest {
        container_id: *container_id,
        timeout: form_param.timeout,
    };
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    let response_buf = service
        .send_recv(5, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => Ok(HttpResponse::Ok().finish()),
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

#[derive(Deserialize)]
struct ExecQueryParam {
    container_id: u32,
    #[serde(default)]
    timeout: u64,
    #[serde(default)]
    capture_size: u64,
}

async fn exec(
    query_param: web::Query<ExecQueryParam>,
    mut payload: actix_multipart::Multipart,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut envs = Vec::new();
    let mut cmds = Vec::new();
    let mut stdin = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        let mut data = vec![];
        while let Some(chunk) = field.next().await {
            data.append(
                &mut chunk
                    .map_err(|e| RestError::Unknown(e.to_string()))?
                    .to_vec(),
            );
        }

        match field.name() {
            "env" => {
                let mut v = String::from_utf8(data)
                    .unwrap_or_default()
                    .split('\n')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                envs.append(&mut v);
            }
            "cmd" => {
                let mut v = String::from_utf8(data)
                    .unwrap_or_default()
                    .split('\n')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                cmds.append(&mut v);
            }
            "stdin" => stdin = data,
            _ => continue,
        }
    }

    let request = ExecRequest {
        container_id: query_param.container_id,
        timeout: query_param.timeout,
        capture_size: query_param.capture_size,
        command: cmds.first().unwrap_or(&String::new()).clone(),
        arguments: cmds.get(1..).map_or(Vec::new(), |v| v.to_vec()),
        envs,
        stdin,
    };
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    let response_buf = service
        .send_recv(6, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => {
            let response: ExecResponse = bincode::deserialize(&response_buf[1..])
                .map_err(|e| RestError::Unknown(e.to_string()))?;
            Ok(HttpResponse::Ok().json(response))
        }
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

#[derive(Deserialize)]
struct KillFormParam {
    signal_num: i32,
}

async fn kill(
    form_param: web::Form<KillFormParam>,
    container_id: web::Path<u32>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let request = KillRequest {
        container_id: *container_id,
        signal_num: form_param.signal_num,
    };
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    let response_buf = service
        .send_recv(7, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => Ok(HttpResponse::Ok().finish()),
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

async fn inspect(
    path_param: Option<web::Path<u32>>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let request = InspectRequest {
        container_id: match path_param {
            Some(id) => *id,
            None => 0,
        },
    };
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;
    let response_buf = service
        .send_recv(8, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => {
            let response: InspectResponse = bincode::deserialize(&response_buf[1..])
                .map_err(|e| RestError::Unknown(e.to_string()))?;
            Ok(HttpResponse::Ok().json(response))
        }
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}

async fn report(
    request: web::Query<ReportRequest>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut request_buf: Vec<u8> =
        bincode::serialize(&*request).map_err(|e| RestError::Unknown(e.to_string()))?;
    let response_buf = service
        .send_recv(9, &mut request_buf)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match response_buf[0] {
        0 => {
            let response: ReportResponse = bincode::deserialize(&response_buf[1..])
                .map_err(|e| RestError::Unknown(e.to_string()))?;
            Ok(HttpResponse::Ok().json(response))
        }
        1 => Err(get_rest_error(&response_buf[1..]).map_err(|e| RestError::Unknown(e.to_string()))?),
        _ => Err(RestError::Unknown("Server response format error".into())),
    }
}
struct ExchangeService {
    stream: Arc<Mutex<UnixStream>>,
}

impl ExchangeService {
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

    async fn send_recv2(&self, command: u8, buf: &mut Vec<u8>, path: &Path) -> Result<Vec<u8>> {
        buf.insert(0, command);

        let mut send_buf = (buf.len() as u32).to_ne_bytes().to_vec();
        send_buf.append(buf);
        acond_io::write_async_lock(self.stream.clone(), &send_buf, send_buf.len()).await?;
        {
            let ref_stream = self.stream.clone();
            let stream = ref_stream.lock().await;
            let file = File::open(path).await?;
            stream.send_fd(file.as_raw_fd()).await?;
            unistd::close(file.as_raw_fd())?;
            unistd::unlink(path)?;
        }

        let recv_buf = acond_io::read_async_lock(self.stream.clone()).await?;
        if recv_buf.is_empty() {
            return Err(anyhow!(utils::ERR_UNEXPECTED));
        }
        Ok(recv_buf)
    }
}

fn get_rest_error(buf: &[u8]) -> Result<RestError> {
    let error: AcondError = bincode::deserialize(buf)?;
    match error.code {
        Code::Unknown => Ok(RestError::Unknown(error.message)),
        Code::InvalidArgument => Ok(RestError::InvalidArgument(error.message)),
        Code::DeadlineExceeded => Ok(RestError::DeadlineExceeded(error.message)),
        Code::PermissionDenied => Ok(RestError::PermissionDenied(error.message)),
    }
}

pub async fn run_server(
    stream: StdUnixStream,
    port: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let service = web::Data::new(ExchangeService::new(UnixStream::from_std(stream)?));

    let ec_group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let ec_key = EcKey::generate(&ec_group)?;
    let pkey = PKey::from_ec_key(ec_key)?;

    let mut x509_builder = X509Builder::new()?;

    let start_time = Asn1Time::days_from_now(0)?;
    let end_time = Asn1Time::days_from_now(365)?;
    x509_builder.set_not_before(&start_time)?;
    x509_builder.set_not_after(&end_time)?;

    let mut x509_name_builder = X509NameBuilder::new()?;
    x509_name_builder.append_entry_by_text("CN", "localhost")?;
    let subject_name = x509_name_builder.build();

    x509_builder.set_subject_name(&subject_name)?;
    x509_builder.set_issuer_name(&subject_name)?;
    x509_builder.set_pubkey(&pkey)?;

    let mut extension = BasicConstraints::new();
    extension.ca();
    x509_builder.append_extension(extension.build()?)?;

    x509_builder.sign(&pkey, MessageDigest::sha384())?;
    let x509 = x509_builder.build();

    HttpServer::new(move || {
        App::new()
            .app_data(service.clone())
            .route("/api/v1/manifest", web::post().to(add_manifest))
            .route("/api/v1/manifest/finalize", web::post().to(finalize))
            .route(
                "/api/v1/manifest/{alg}/{hash1}/{hash2}",
                web::get().to(get_manifest),
            )
            .route("/api/v1/blob/{name}", web::put().to(add_blob))
            .route("/api/v1/blob/{name}", web::get().to(get_blob_size))
            .route("/api/v1/container/start", web::post().to(start))
            .route("/api/v1/container/{id}/restart", web::post().to(restart))
            .route("/api/v1/container/exec", web::post().to(exec))
            .route("/api/v1/container/{id}/kill", web::post().to(kill))
            .route("/api/v1/container/{id}/inspect", web::get().to(inspect))
            .route("/api/v1/container/inspect", web::get().to(inspect))
            .route("/api/v1/container/report", web::get().to(report))
    })
    .bind_openssl(format!("0.0.0.0:{}", port), {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key(&pkey)?;
        builder.set_certificate(&x509)?;
        builder
    })?
    .run()
    .await?;

    Ok(())
}

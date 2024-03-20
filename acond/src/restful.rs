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
use actix_multipart::Multipart;
use actix_web::{
    http::{self, StatusCode},
    web, App, HttpResponse, HttpServer, ResponseError,
};
use anyhow::{anyhow, Result};
use futures::{StreamExt, TryStreamExt};
use nix::unistd;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod},
    x509::{extension::BasicConstraints, X509Builder, X509NameBuilder},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fmt, fs,
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
    mut payload: Multipart,
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
struct Alg {
    alg: u32,
}

async fn add_blob(
    blob_name: web::Path<String>,
    blob_alg: web::Query<Alg>,
    mut payload: Multipart,
    range: Option<web::Header<http::header::ContentRange>>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let blob_name = format!("/tmp/{}", blob_name.into_inner());
    let blob_path = Path::new(blob_name.as_str());
    fs::create_dir_all(blob_path.parent().unwrap())
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    loop {
        let field = payload
            .try_next()
            .await
            .map_err(|e| RestError::Unknown(e.to_string()))?;
        if field.is_none() {
            break;
        }

        let mut field = field.unwrap();
        if let Some(ref value) = range {
            let range = value.0.to_string();
            let start = utils::parse_content_range(&range).unwrap_or(0);

            if blob_path.exists() {
                let metadata = blob_path
                    .metadata()
                    .map_err(|e| RestError::Unknown(e.to_string()))?;
                if start > metadata.len() {
                    return Err(RestError::InvalidArgument(
                        "Start of Content range parameter is bigger than existing file.".into(),
                    ));
                }
            }

            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(blob_path)
                .await
                .map_err(|e| RestError::Unknown(e.to_string()))?;
            f.seek(SeekFrom::Start(start))
                .await
                .map_err(|e| RestError::Unknown(e.to_string()))?;

            while let Some(chunk) = field.next().await {
                let data = chunk.map_err(|e| RestError::Unknown(e.to_string()))?;
                f.write_all(&data)
                    .await
                    .map_err(|e| RestError::Unknown(e.to_string()))?;
            }
        } else {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(blob_path)
                .await
                .map_err(|e| RestError::Unknown(e.to_string()))?;

            while let Some(chunk) = field.next().await {
                let data = chunk.map_err(|e| RestError::Unknown(e.to_string()))?;
                f.write_all(&data)
                    .await
                    .map_err(|e| RestError::Unknown(e.to_string()))?;
            }
        }
    }

    let inner_request = AddBlobRequest {
        alg: blob_alg.into_inner().alg,
        data: vec![],
    };
    let mut request_buf: Vec<u8> =
        bincode::serialize(&inner_request).map_err(|e| RestError::Unknown(e.to_string()))?;
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
    let blob_name = format!("/tmp/{}", blob_name.into_inner());
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

async fn start(
    mut payload: web::Payload,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|e| RestError::Unknown(e.to_string()))?;
        body.extend_from_slice(&chunk);
    }

    let mut data: HashMap<String, Vec<String>> = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(body.as_ref()) {
        data.entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }

    let image_id = data
        .remove("image_id")
        .and_then(|mut v| v.pop())
        .unwrap_or_default();
    let envs = data.remove("envs").unwrap_or_default();

    let request = StartRequest { image_id, envs };
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

async fn restart(
    request: web::Form<RestartRequest>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request.into_inner()).map_err(|e| RestError::Unknown(e.to_string()))?;

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

async fn exec(
    mut payload: actix_multipart::Multipart,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut request = ExecRequest::default();

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
            "container_id" => {
                request.container_id = utils::convert_ascii_bytes_to_u32(&data)
                    .map_err(|e| RestError::InvalidArgument(e.to_string()))?
            }
            "command" => {
                request.command = String::from_utf8(data)
                    .map_err(|e| RestError::InvalidArgument(e.to_string()))?
            }
            "timeout" => {
                request.timeout = utils::convert_ascii_bytes_to_u64(&data)
                    .map_err(|e| RestError::InvalidArgument(e.to_string()))?
            }
            "arguments" => request.arguments.push(
                String::from_utf8(data).map_err(|e| RestError::InvalidArgument(e.to_string()))?,
            ),
            "envs" => request.envs.push(
                String::from_utf8(data).map_err(|e| RestError::InvalidArgument(e.to_string()))?,
            ),
            "stdin" => request.stdin = data,
            "capture_size" => {
                request.capture_size = utils::convert_ascii_bytes_to_u64(&data)
                    .map_err(|e| RestError::InvalidArgument(e.to_string()))?
            }
            _ => continue,
        }
    }

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

async fn kill(
    request: web::Form<KillRequest>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request.into_inner()).map_err(|e| RestError::Unknown(e.to_string()))?;

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
    request: web::Query<InspectRequest>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut request_buf: Vec<u8> =
        bincode::serialize(&request.into_inner()).map_err(|e| RestError::Unknown(e.to_string()))?;
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
        bincode::serialize(&request.into_inner()).map_err(|e| RestError::Unknown(e.to_string()))?;
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

    let rsa_key = Rsa::generate(3072)?;
    let private_key = PKey::from_rsa(rsa_key)?;

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
    x509_builder.set_pubkey(&private_key)?;

    let mut extension = BasicConstraints::new();
    extension.ca();
    x509_builder.append_extension(extension.build()?)?;

    x509_builder.sign(&private_key, MessageDigest::sha384())?;
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
            .route("/api/v1/container/restart", web::post().to(restart))
            .route("/api/v1/container/exec", web::post().to(exec))
            .route("/api/v1/container/kill", web::post().to(kill))
            .route("/api/v1/container/inspect", web::get().to(inspect))
            .route("/api/v1/container/report", web::get().to(report))
    })
    .workers(10)
    .bind_openssl(format!("0.0.0.0:{}", port), {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key(&private_key)?;
        builder.set_certificate(&x509)?;
        builder
    })?
    .run()
    .await?;

    Ok(())
}

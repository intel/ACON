// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::Config,
    oidc,
    server::{
        AcondError, AddBlobRequest, AddManifestRequest, AddManifestResponse, Code, ExecRequest,
        ExecResponse, GetManifestRequest, GetManifestResponse, InspectRequest, InspectResponse,
        KillRequest, ReportRequest, ReportResponse, RestartRequest, StartRequest, StartResponse,
    },
    utils,
};
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    error,
    http::header,
    http::{
        self,
        header::{ContentRange, ContentRangeSpec},
        StatusCode,
    },
    web, App, Error, HttpRequest, HttpResponse, HttpServer, ResponseError,
};
use actix_web_lab::middleware::{from_fn, Next};
use anyhow::Result;
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
    pkey::{PKey, Private},
    rand,
    sign::Signer,
    ssl::{SslAcceptor, SslMethod},
    x509::{extension::BasicConstraints, X509Builder, X509NameBuilder},
};
use std::{
    env, fmt,
    io::SeekFrom,
    os::{fd::AsRawFd, unix::net::UnixStream as StdUnixStream},
    path::Path,
    sync::Arc,
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::UnixStream,
    sync::{Mutex, RwLock},
};
use tokio_send_fd::SendFd;

const DEF_HASH_ALG: u32 = 2;
const DEF_TIMEOUT: u64 = 30;
const DEF_CAP_SIZE: u64 = 0x20000;
const ERR_REQ_CONTENT_RANGE: &str = "The start of content range is bigger than the existing file";
const ERR_RESP_FORMAT: &str = "Server response format error";
const ERR_RESP_INVALID_SESSION: &str = "Invalid session or session expired";

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
        match field.name() {
            "manifest" => request.manifest = read_multipart_data(&mut field).await?,
            "sig" => request.signature = read_multipart_data(&mut field).await?,
            "cert" => request.certificate = read_multipart_data(&mut field).await?,
            _ => continue,
        }
    }

    let send_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(1, send_buf, None, service, |data| {
        let response: AddManifestResponse =
            bincode::deserialize(data).map_err(|e| RestError::Unknown(e.to_string()))?;
        Ok(HttpResponse::Ok().json(response))
    })
    .await
}

async fn finalize(service: web::Data<ExchangeService>) -> Result<HttpResponse, RestError> {
    do_exchange(2, vec![0; 0], None, service, |_| {
        Ok(HttpResponse::Ok().finish())
    })
    .await
}

async fn get_manifest(
    path: web::Path<(String, String, String)>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let request = GetManifestRequest {
        image_id: format!("{}/{}/{}", path.0, path.1, path.2),
    };
    let send_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(10, send_buf, None, service, |data| {
        let response: GetManifestResponse =
            bincode::deserialize(data).map_err(|e| RestError::Unknown(e.to_string()))?;
        Ok(HttpResponse::Ok().json(response))
    })
    .await
}

#[derive(serde::Deserialize)]
struct AddBlobQueryParam {
    #[serde(default = "set_default_alg")]
    alg: u32,
}

fn set_default_alg() -> u32 {
    DEF_HASH_ALG
}

async fn add_blob(
    blob_name: web::Path<String>,
    query_param: web::Query<AddBlobQueryParam>,
    range: Option<web::Header<http::header::ContentRange>>,
    mut payload: web::Payload,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let blob_name = format!("{}/{}", utils::BLOB_DIR, *blob_name);
    let blob_path = Path::new(blob_name.as_str());

    let mut start = 0;
    if let Some(content_range) = range {
        if let ContentRange(ContentRangeSpec::Bytes {
            range: Some((s, _)),
            ..
        }) = *content_range
        {
            start = s;
        }
    }

    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(blob_path)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    fcntl::flock(f.as_raw_fd(), FlockArg::LockExclusiveNonblock)
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    let metadata = f
        .metadata()
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    if start > metadata.len() {
        return Err(RestError::InvalidArgument(ERR_REQ_CONTENT_RANGE.into()));
    }

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

    f.flush()
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    let request = AddBlobRequest {
        alg: query_param.alg,
        data: vec![],
    };
    let send_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(3, send_buf, Some(blob_path), service, |_| {
        Ok(HttpResponse::Ok().finish())
    })
    .await
}

async fn get_blob_size(blob_name: web::Path<String>) -> Result<HttpResponse, RestError> {
    let f = OpenOptions::new()
        .read(true)
        .open(format!("{}/{}", utils::BLOB_DIR, *blob_name))
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    fcntl::flock(f.as_raw_fd(), FlockArg::LockSharedNonblock)
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    let metadata = f
        .metadata()
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    Ok(HttpResponse::Ok().json(metadata.len()))
}

#[derive(serde::Deserialize)]
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
        match field.name() {
            "env" => envs.append(&mut parse_bytes_to_strings(
                read_multipart_data(&mut field).await?,
            )),
            _ => continue,
        }
    }

    let request = StartRequest {
        image_id: query_param.image_id.clone(),
        envs,
    };
    let send_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(4, send_buf, None, service, |data| {
        let response: StartResponse =
            bincode::deserialize(data).map_err(|e| RestError::Unknown(e.to_string()))?;
        Ok(HttpResponse::Ok().json(response))
    })
    .await
}

#[derive(serde::Deserialize)]
struct RestartQueryParam {
    #[serde(default = "set_default_timeout")]
    timeout: u64,
}

fn set_default_timeout() -> u64 {
    DEF_TIMEOUT
}

async fn restart(
    query_param: web::Query<RestartQueryParam>,
    container_id: web::Path<u32>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let request = RestartRequest {
        container_id: *container_id,
        timeout: query_param.timeout,
    };
    let send_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(5, send_buf, None, service, |_| {
        Ok(HttpResponse::Ok().finish())
    })
    .await
}

#[derive(serde::Deserialize)]
struct ExecQueryParam {
    #[serde(default = "set_default_timeout")]
    timeout: u64,
    #[serde(default = "set_default_capsize")]
    capture_size: u64,
}

fn set_default_capsize() -> u64 {
    DEF_CAP_SIZE
}

async fn exec(
    query_param: web::Query<ExecQueryParam>,
    container_id: web::Path<u32>,
    mut payload: actix_multipart::Multipart,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let mut envs = Vec::new();
    let mut cmds = Vec::new();
    let mut stdin = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        match field.name() {
            "env" => envs.append(&mut parse_bytes_to_strings(
                read_multipart_data(&mut field).await?,
            )),
            "cmd" => cmds.append(&mut parse_bytes_to_strings(
                read_multipart_data(&mut field).await?,
            )),
            "stdin" => stdin.append(&mut read_multipart_data(&mut field).await?),
            _ => continue,
        }
    }

    let request = ExecRequest {
        container_id: *container_id,
        timeout: query_param.timeout,
        capture_size: query_param.capture_size,
        command: cmds.first().unwrap_or(&String::new()).clone(),
        arguments: cmds.get(1..).map_or(Vec::new(), |v| v.to_vec()),
        envs,
        stdin,
    };
    let send_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(6, send_buf, None, service, |data| {
        let response: ExecResponse =
            bincode::deserialize(data).map_err(|e| RestError::Unknown(e.to_string()))?;
        Ok(HttpResponse::Ok().json(response))
    })
    .await
}

#[derive(serde::Deserialize)]
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
    let send_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(7, send_buf, None, service, |_| {
        Ok(HttpResponse::Ok().finish())
    })
    .await
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
    let send_buf: Vec<u8> =
        bincode::serialize(&request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(8, send_buf, None, service, |data| {
        let response: InspectResponse =
            bincode::deserialize(data).map_err(|e| RestError::Unknown(e.to_string()))?;
        Ok(HttpResponse::Ok().json(response))
    })
    .await
}

async fn report(
    request: web::Query<ReportRequest>,
    service: web::Data<ExchangeService>,
) -> Result<HttpResponse, RestError> {
    let send_buf: Vec<u8> =
        bincode::serialize(&*request).map_err(|e| RestError::Unknown(e.to_string()))?;

    do_exchange(9, send_buf, None, service, |data| {
        let response: ReportResponse =
            bincode::deserialize(data).map_err(|e| RestError::Unknown(e.to_string()))?;
        Ok(HttpResponse::Ok().json(response))
    })
    .await
}

#[derive(serde::Deserialize)]
struct LoginFormParam {
    client_id: String,
    client_secret: String,
    device_code: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_timeout: Option<i64>,
}

async fn login(
    form_param: web::Form<LoginFormParam>,
    service: web::Data<ExchangeService>,
    req: HttpRequest,
) -> Result<HttpResponse, RestError> {
    if let Some(secret) = req.headers().get(header::AUTHORIZATION) {
        if let Some(pkey) = service.hmac_key.read().await.as_deref() {
            if oidc::verify_secret(secret, pkey) {
                if let Ok(s) = secret.to_str() {
                    return Ok(HttpResponse::Ok().json(s));
                }
            }
        }
    }

    let mut secret = oidc::verify_id_token(
        &form_param.client_id,
        &form_param.client_secret,
        &form_param.device_code,
        form_param.expires_in,
        form_param.session_timeout,
        &service.openid_user,
    )
    .await
    .map_err(|e| RestError::Unknown(e.to_string()))?;

    let pkey = service
        .refresh_hmac_key()
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    let mut signer = Signer::new(MessageDigest::sha384(), &pkey)
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    signer
        .update(&secret)
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    let mut hmac = signer
        .sign_to_vec()
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    secret.append(&mut hmac);

    Ok(HttpResponse::Ok().json(data_encoding::HEXUPPER.encode(&secret)))
}

async fn logout(service: web::Data<ExchangeService>) -> Result<HttpResponse, RestError> {
    service
        .refresh_hmac_key()
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;
    Ok(HttpResponse::Ok().finish())
}

async fn verify_client<B>(
    service: web::Data<ExchangeService>,
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody,
{
    if service.openid_user.is_none() {
        return next.call(req).await;
    }

    if !req.path().ends_with("/login") {
        let key = service.hmac_key.read().await;
        let pkey = key
            .as_deref()
            .ok_or(error::ErrorUnauthorized(ERR_RESP_INVALID_SESSION))?;
        let secret = req
            .headers()
            .get(header::AUTHORIZATION)
            .ok_or(error::ErrorUnauthorized(ERR_RESP_INVALID_SESSION))?;
        if !oidc::verify_secret(secret, pkey) {
            return Err(error::ErrorUnauthorized(ERR_RESP_INVALID_SESSION));
        }
    }

    next.call(req).await
}

async fn do_exchange<F>(
    command: u8,
    mut buf: Vec<u8>,
    path: Option<&Path>,
    service: web::Data<ExchangeService>,
    on_success: F,
) -> Result<HttpResponse, RestError>
where
    F: Fn(&[u8]) -> Result<HttpResponse, RestError>,
{
    buf.insert(0, command);
    let mut send_buf = (buf.len() as u32).to_ne_bytes().to_vec();
    send_buf.append(&mut buf);

    let recv_buf: Vec<u8> = service
        .do_exchange(&send_buf, path)
        .await
        .map_err(|e| RestError::Unknown(e.to_string()))?;

    match recv_buf.first() {
        Some(0) => on_success(recv_buf.get(1..).unwrap_or(&[])),
        Some(1) => {
            let error: AcondError = bincode::deserialize(recv_buf.get(1..).unwrap_or(&[]))
                .map_err(|e| RestError::Unknown(e.to_string()))?;
            match error.code {
                Code::Unknown => Err(RestError::Unknown(error.message)),
                Code::InvalidArgument => Err(RestError::InvalidArgument(error.message)),
                Code::DeadlineExceeded => Err(RestError::DeadlineExceeded(error.message)),
                Code::PermissionDenied => Err(RestError::PermissionDenied(error.message)),
            }
        }
        _ => Err(RestError::Unknown(ERR_RESP_FORMAT.into())),
    }
}

async fn read_multipart_data(field: &mut actix_multipart::Field) -> Result<Vec<u8>, RestError> {
    let mut data = vec![];
    while let Some(chunk) = field.next().await {
        data.append(
            &mut chunk
                .map_err(|e| RestError::Unknown(e.to_string()))?
                .to_vec(),
        );
    }

    Ok(data)
}

fn parse_bytes_to_strings(data: Vec<u8>) -> Vec<String> {
    String::from_utf8(data)
        .unwrap_or_default()
        .split('\n')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

struct ExchangeService {
    stream: Arc<Mutex<UnixStream>>,
    hmac_key: RwLock<Option<PKey<Private>>>,
    openid_user: Option<String>,
}

impl ExchangeService {
    fn new(stream: UnixStream, openid_user: Option<String>) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            hmac_key: RwLock::new(None::<PKey<Private>>),
            openid_user,
        }
    }

    async fn do_exchange(&self, buf: &[u8], path: Option<&Path>) -> Result<Vec<u8>> {
        let ref_stream = self.stream.clone();
        let mut stream = ref_stream.lock().await;
        stream.write_all(buf).await?;

        if let Some(path) = path {
            let file = File::open(path).await?;
            stream.send_fd(file.as_raw_fd()).await?;
            unistd::close(file.as_raw_fd())?;
            unistd::unlink(path)?;
        }

        let mut buf = Vec::new();
        let mut chunk = [0u8; utils::BUFF_SIZE];
        loop {
            match stream.read(&mut chunk).await {
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if n < chunk.len() {
                        break;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(buf)
    }

    async fn refresh_hmac_key(&self) -> Result<PKey<Private>> {
        let mut key = [0; 128];
        rand::rand_bytes(&mut key)?;
        let pkey = PKey::hmac(&key)?;

        let mut hmac_key = self.hmac_key.write().await;
        *hmac_key = Some(pkey.clone());

        Ok(pkey)
    }
}

pub async fn run_server(
    stream: StdUnixStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(proxy) = config.https_proxy.as_ref() {
        env::set_var("https_proxy", proxy);
    }

    let service = web::Data::new(ExchangeService::new(
        UnixStream::from_std(stream)?,
        config.openid_user.clone(),
    ));

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
            .wrap(from_fn(verify_client))
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
            .route("/api/v1/container/{id}/exec", web::post().to(exec))
            .route("/api/v1/container/{id}/kill", web::post().to(kill))
            .route("/api/v1/container/{id}/inspect", web::get().to(inspect))
            .route("/api/v1/container/inspect", web::get().to(inspect))
            .route("/api/v1/container/report", web::get().to(report))
            .route("/api/v1/oauth2/login", web::post().to(login))
            .route("/api/v1/oauth2/logout", web::post().to(logout))
    })
    .bind_openssl(format!("0.0.0.0:{}", config.tcp_port), {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key(&pkey)?;
        builder.set_certificate(&x509)?;
        builder
    })?
    .run()
    .await?;

    Ok(())
}

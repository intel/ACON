// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::{image::AttestDataValue, pod::Pod, report, utils};
use anyhow::{anyhow, Result};
use std::{
    fs::{self, Permissions},
    io::ErrorKind,
    mem,
    os::unix::prelude::PermissionsExt,
    path::Path,
    str,
    sync::Arc,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot, watch, RwLock},
};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AconMessageHdr {
    command: i32, // even = request; odd = response; negative = error
    size: u32,    // size of the whole request/response
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AconMessageErr {
    header: AconMessageHdr, // command = -Exxx, as defintion in Linux
    request: i32,           // original request code
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AconGetReportReq {
    header: AconMessageHdr, // command = 0
    is_quote: bool,
    nonce: [u64; 2],
    data_type: i32, // 0 = no data; 1 = binary; 2 = string; others = reserved
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AconGetReportRsp {
    header: AconMessageHdr, // command = 1
    rtmr_count: i32,
    report: [u8; report::REPORT_SIZE],
    quote_offset: i32,
    attestation_json_offset: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AconSetAttestationDataReq {
    header: AconMessageHdr, // command = 2
    data_type: i32,         // Same definition as AconGetReportReq.dataType
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AconSetAttestationDataRsp {
    header: AconMessageHdr, // command = 3
}

#[repr(C)]
union AconReq {
    header: AconMessageHdr,
    get_report: AconGetReportReq,
    set_attestation_data: AconSetAttestationDataReq,
}

#[repr(C)]
#[allow(unused)]
union AconRsp {
    header: AconMessageHdr,
    error: AconMessageErr,
    get_report: AconGetReportRsp,
    set_attestation_data: AconSetAttestationDataRsp,
}

struct Request {
    command: i32,
    bytes: Vec<u8>,
    uid: u32,
    resp_tx: oneshot::Sender<Vec<u8>>,
}

struct AconService {
    pod: Arc<RwLock<Pod>>,
}

impl AconService {
    async fn get_report(
        &self,
        uid: u32,
        is_quote: bool,
        nonce: [u64; 2],
        dtype: i32,
        data: String,
    ) -> Result<(i32, [u8; report::REPORT_SIZE], Option<Vec<u8>>, String)> {
        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;

        let (requestor_nonce, acond_nonce) = utils::get_nounces(nonce[0], nonce[1])?;
        let attest_data = pod.get_attestation_data(
            requestor_nonce,
            acond_nonce,
            Some((uid, AttestDataValue::DataValue { dtype, data })),
        )?;

        if is_quote {
            let (report, quote) = report::get_quote(&attest_data)?;
            Ok((report::NUM_RTMRS, report, Some(quote), attest_data))
        } else {
            let report = report::get_report(&attest_data)?;
            Ok((report::NUM_RTMRS, report, None, attest_data))
        }
    }

    async fn set_attestation_data(&self, uid: u32, dtype: i32, data: String) -> Result<()> {
        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;

        let container = pod.get_container_mut(&uid).unwrap();
        container.attest_data = AttestDataValue::DataValue { dtype, data };

        Ok(())
    }
}

pub unsafe fn convert_attest_data(dtype: i32, data: &[u8]) -> &str {
    match dtype {
        1 => str::from_utf8_unchecked(data),
        _ => {
            let end = data.iter().position(|&c| c == b'\0').unwrap_or(data.len());
            str::from_utf8_unchecked(&data[0..end])
        }
    }
}

fn convert_error_bytes(command: i32, err: &str) -> Vec<u8> {
    let err_bytes = err.as_bytes();
    let err_bytes_offset = mem::size_of::<AconMessageErr>();

    let mut msg_err_bytes: Vec<u8> = vec![0; err_bytes_offset + err_bytes.len()];
    let msg_err = msg_err_bytes.as_mut_ptr() as *mut AconMessageErr;
    unsafe {
        (*msg_err).header.command = -1; // Not know errno.
        (*msg_err).header.size = msg_err_bytes.len() as u32;
        (*msg_err).request = command;
    }

    for i in 0..err_bytes.len() {
        msg_err_bytes[err_bytes_offset + i] = err_bytes[i];
    }

    msg_err_bytes
}

async fn handle_request(stream: UnixStream, tx: mpsc::Sender<Request>) -> Result<()> {
    let mut req_bytes: Vec<u8> = vec![0; mem::size_of::<AconReq>()];
    let mut req_bytes_offset = 0;
    let mut data_size = 0;

    loop {
        stream.readable().await?;
        match stream.try_read(&mut req_bytes[req_bytes_offset..]) {
            Ok(n) => {
                if req_bytes_offset == 0 {
                    data_size =
                        unsafe { (*(req_bytes.as_mut_ptr() as *mut AconMessageHdr)).size as usize };
                }

                if req_bytes_offset + n >= data_size {
                    break;
                }

                req_bytes_offset += n;
                req_bytes.resize(data_size, 0);
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }

    let resp_bytes = {
        if data_size < mem::size_of::<AconMessageHdr>() {
            utils::ERR_IPC_INVALID_REQUEST.as_bytes().to_vec()
        } else {
            let (resp_tx, resp_rx) = oneshot::channel();
            let request = Request {
                command: unsafe { (*(req_bytes.as_mut_ptr() as *mut AconMessageHdr)).command },
                bytes: req_bytes[0..data_size as usize].to_vec(),
                uid: stream.peer_cred()?.uid(),
                resp_tx,
            };

            let _ = tx.send(request).await;
            resp_rx.await?
        }
    };

    loop {
        stream.writable().await?;
        match stream.try_write(&resp_bytes) {
            Ok(_) => return Ok(()),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

async fn monitor_request(pod: Arc<RwLock<Pod>>, mut rx: mpsc::Receiver<Request>) {
    let service = AconService { pod };

    loop {
        if let Some(request) = rx.recv().await {
            match dispatch_request(&request, &service).await {
                Ok(response) => {
                    let _ = request.resp_tx.send(response);
                }
                Err(e) => {
                    let _ = request
                        .resp_tx
                        .send(convert_error_bytes(request.command, &e.to_string()));
                }
            }
        }
    }
}

async fn dispatch_request(request: &Request, service: &AconService) -> Result<Vec<u8>> {
    match request.command {
        0 => {
            let (is_quote, attest_nonce, attest_data_type, attest_data) = unsafe {
                let get_report_req = request.bytes.as_ptr() as *const AconGetReportReq;
                (
                    (*get_report_req).is_quote,
                    (*get_report_req).nonce,
                    (*get_report_req).data_type,
                    convert_attest_data(
                        (*get_report_req).data_type,
                        &request.bytes[mem::size_of::<AconGetReportReq>()..],
                    )
                    .to_owned(),
                )
            };

            match service
                .get_report(
                    request.uid,
                    is_quote,
                    attest_nonce,
                    attest_data_type,
                    attest_data,
                )
                .await
            {
                Ok((rtmr_count, report, quote, attest_data)) => {
                    let attest_data_bytes: &[u8] = attest_data.as_bytes();
                    let quote_offset = mem::size_of::<AconGetReportRsp>();
                    let mut attest_json_offset = quote_offset;
                    if let Some(ref quote_bytes) = quote {
                        attest_json_offset += quote_bytes.len();
                    }

                    let mut resp_bytes: Vec<u8> =
                        vec![0; attest_json_offset + attest_data_bytes.len()];
                    let get_report_resp = resp_bytes.as_mut_ptr() as *mut AconGetReportRsp;

                    unsafe {
                        (*get_report_resp).header.command = request.command + 1;
                        (*get_report_resp).header.size = resp_bytes.len() as u32;
                        (*get_report_resp).rtmr_count = rtmr_count;
                        (*get_report_resp).report = report;
                        (*get_report_resp).quote_offset = quote_offset as i32;
                        (*get_report_resp).attestation_json_offset = attest_json_offset as i32;
                    }

                    if let Some(quote_bytes) = quote {
                        for i in 0..quote_bytes.len() {
                            resp_bytes[quote_offset + i] = quote_bytes[i];
                        }
                    }

                    for i in 0..attest_data_bytes.len() {
                        resp_bytes[attest_json_offset + i] = attest_data_bytes[i];
                    }

                    Ok(resp_bytes)
                }
                Err(e) => Ok(convert_error_bytes(request.command, &e.to_string())),
            }
        }

        2 => {
            let (attest_data_type, attest_data) = unsafe {
                let set_attestation_data_req =
                    request.bytes.as_ptr() as *const AconSetAttestationDataReq;

                (
                    (*set_attestation_data_req).data_type,
                    convert_attest_data(
                        (*set_attestation_data_req).data_type,
                        &request.bytes[mem::size_of::<AconSetAttestationDataReq>()..],
                    )
                    .to_owned(),
                )
            };

            if let Err(e) = service
                .set_attestation_data(request.uid, attest_data_type, attest_data)
                .await
            {
                Ok(convert_error_bytes(request.command, &e.to_string()))
            } else {
                let mut resp_bytes: Vec<u8> = vec![0; mem::size_of::<AconSetAttestationDataRsp>()];
                let set_attestation_data_rsp =
                    resp_bytes.as_mut_ptr() as *mut AconSetAttestationDataRsp;

                unsafe {
                    (*set_attestation_data_rsp).header.command = request.command + 1;
                    (*set_attestation_data_rsp).header.size = resp_bytes.len() as u32;
                }

                Ok(resp_bytes)
            }
        }

        _ => Err(anyhow!(utils::ERR_IPC_NOT_SUPPORTED)),
    }
}

pub async fn run_unix_server(
    pod: Arc<RwLock<Pod>>,
    path: &str,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let unix_path = Path::new(path);

    if unix_path.exists() {
        fs::remove_file(unix_path)?;
    }
    fs::create_dir_all(unix_path.parent().unwrap())?;

    tokio::select! {
        res = async {
            let (tx, rx) = mpsc::channel(100);
            tokio::spawn(monitor_request(pod, rx));

            let listener = UnixListener::bind(unix_path)?;
            fs::set_permissions(unix_path, Permissions::from_mode(0o666))?;

            loop {
                let (stream, _) = listener.accept().await?;
                tokio::spawn(handle_request(stream, tx.clone()));
            }
        } => {
            res
        }

        _ = shutdown.changed() => {
            Ok(())
        }
    }
}

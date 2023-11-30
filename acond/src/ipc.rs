// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::{image::AttestDataValue, pod::Pod, report, utils};
use anyhow::{anyhow, Result};
use std::{
    fs::{self, Permissions},
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
    request_type: u32,      // 0 is report and 1 is quote
    nonce: [u64; 2],
    attest_data_type: i32, // 0 = no data; 1 = binary; 2 = string; others = reserved
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AconGetReportRsp {
    header: AconMessageHdr, // command = 1
    rtmr_log_offset: i32,
    attestation_json_offset: i32,
    data_offset: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AconSetAttestationDataReq {
    header: AconMessageHdr, // command = 2
    attest_data_type: i32,  // Same definition as AconGetReportReq.attest_data_type
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
        request_type: u32,
        nonce: [u64; 2],
        attest_data_type: i32,
        attest_data: String,
    ) -> Result<(String, String, Vec<u8>)> {
        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;

        let (requestor_nonce, acond_nonce) = utils::get_nounces(nonce[0], nonce[1])?;
        let attest_data = pod.get_attestation_data(
            requestor_nonce,
            acond_nonce,
            Some((
                uid,
                AttestDataValue::DataValue {
                    dtype: attest_data_type,
                    data: attest_data,
                },
            )),
        )?;
        let mut rtmr_log = "\0\0\0".to_string(); // log of 0-2 is dismissed.
        let rtmr_log3 = utils::get_measurement_rtmr3()?;
        for l in rtmr_log3.iter() {
            rtmr_log.push_str(l);
            rtmr_log.push_str("\0");
        }

        match request_type {
            0 => {
                let report = report::get_report(&attest_data)?;
                Ok((rtmr_log, attest_data, report))
            }
            1 => {
                let quote = report::get_quote(&attest_data)?;
                Ok((rtmr_log, attest_data, quote))
            }
            _ => Err(anyhow!(utils::ERR_RPC_INVALID_REQUEST_TYPE)),
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

unsafe fn bytes_to_string(data: &[u8]) -> String {
    str::from_utf8_unchecked(&data[..data.iter().position(|&c| c == b'\0').unwrap_or(data.len())])
        .into()
}

fn error_to_vec(command: i32, err: &str) -> Vec<u8> {
    let err_bytes = err.as_bytes();
    let offset = mem::size_of::<AconMessageErr>();

    let mut msg_err_bytes: Vec<u8> = vec![0; offset + err_bytes.len()];
    let msg_err = msg_err_bytes.as_mut_ptr() as *mut AconMessageErr;
    unsafe {
        (*msg_err).header.command = -1; // Not know errno.
        (*msg_err).header.size = msg_err_bytes.len() as u32;
        (*msg_err).request = command;
    }

    msg_err_bytes[offset..(offset + err_bytes.len())].copy_from_slice(err_bytes);
    msg_err_bytes
}

async fn handle_request(stream: UnixStream, tx: mpsc::Sender<Request>) -> Result<()> {
    let mut req_bytes: Vec<u8> = vec![0; mem::size_of::<AconReq>()];
    let mut offset = 0;
    let mut data_size = 0;

    loop {
        stream.readable().await?;
        match stream.try_read(&mut req_bytes[offset..]) {
            Ok(n) => {
                if offset == 0 {
                    data_size =
                        unsafe { (*(req_bytes.as_ptr() as *const AconMessageHdr)).size as usize };
                    req_bytes.resize(data_size, 0);
                }

                if offset + n >= data_size {
                    break;
                }

                offset += n;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let resp_bytes = match data_size {
        size if size < mem::size_of::<AconMessageHdr>() => {
            utils::ERR_IPC_INVALID_REQUEST.as_bytes().to_vec()
        }
        _ => {
            let (resp_tx, resp_rx) = oneshot::channel();
            let request = Request {
                command: unsafe { (*(req_bytes.as_ptr() as *const AconMessageHdr)).command },
                bytes: req_bytes[..data_size].to_vec(),
                uid: stream.peer_cred()?.uid(),
                resp_tx,
            };

            let _ = tx.send(request).await;
            resp_rx.await?
        }
    };

    loop {
        let mut offset = 0;

        stream.writable().await?;
        match stream.try_write(&resp_bytes) {
            Ok(n) => {
                offset += n;
                if offset == resp_bytes.len() {
                    return Ok(());
                }
            }
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
                        .send(error_to_vec(request.command, &e.to_string()));
                }
            }
        }
    }
}

async fn dispatch_request(request: &Request, service: &AconService) -> Result<Vec<u8>> {
    match request.command {
        0 => {
            let (request_type, attest_nonce, attest_data_type, attest_data) = unsafe {
                let get_report_req = request.bytes.as_ptr() as *const AconGetReportReq;
                (
                    (*get_report_req).request_type,
                    (*get_report_req).nonce,
                    (*get_report_req).attest_data_type,
                    bytes_to_string(&request.bytes[mem::size_of::<AconGetReportReq>()..]),
                )
            };

            match service
                .get_report(
                    request.uid,
                    request_type,
                    attest_nonce,
                    attest_data_type,
                    attest_data,
                )
                .await
            {
                Ok((rtmr_log, attest_data, data)) => {
                    let rtmr_log_bytes = rtmr_log.as_bytes();
                    let rtmr_log_offset = mem::size_of::<AconGetReportRsp>();
                    let attest_data_bytes: &[u8] = attest_data.as_bytes();
                    let attest_json_offset = rtmr_log_offset + rtmr_log_bytes.len();
                    let data_offset = attest_json_offset + attest_data_bytes.len();

                    let mut resp_bytes: Vec<u8> = vec![0; data_offset + data.len()];
                    let get_report_resp = resp_bytes.as_mut_ptr() as *mut AconGetReportRsp;

                    unsafe {
                        (*get_report_resp).header.command = request.command + 1;
                        (*get_report_resp).header.size = resp_bytes.len() as u32;
                        (*get_report_resp).rtmr_log_offset = rtmr_log_offset as i32;
                        (*get_report_resp).attestation_json_offset = attest_json_offset as i32;
                        (*get_report_resp).data_offset = data_offset as i32;
                    }

                    resp_bytes[rtmr_log_offset..(rtmr_log_offset + rtmr_log_bytes.len())]
                        .copy_from_slice(&rtmr_log_bytes);
                    resp_bytes[attest_json_offset..(attest_json_offset + attest_data_bytes.len())]
                        .copy_from_slice(attest_data_bytes);
                    resp_bytes[data_offset..(data_offset + data.len())].copy_from_slice(&data);

                    Ok(resp_bytes)
                }
                Err(e) => Ok(error_to_vec(request.command, &e.to_string())),
            }
        }

        2 => {
            let (attest_data_type, attest_data) = unsafe {
                let set_attestation_data_req =
                    request.bytes.as_ptr() as *const AconSetAttestationDataReq;

                (
                    (*set_attestation_data_req).attest_data_type,
                    bytes_to_string(&request.bytes[mem::size_of::<AconSetAttestationDataReq>()..]),
                )
            };

            if let Err(e) = service
                .set_attestation_data(request.uid, attest_data_type, attest_data)
                .await
            {
                Ok(error_to_vec(request.command, &e.to_string()))
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

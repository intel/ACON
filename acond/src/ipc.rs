// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    image::AttestDataValue,
    pod::Pod,
    utils::{self, NUM_RTMRS, REPORT_SIZE},
};
use anyhow::{anyhow, Result};

use serde::{Deserialize, Serialize};
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
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
struct AconMessageHdr {
    command: i32, // even = request; odd = response; negative = error
    size: u32,    // size of the whole request/response
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct AconMessageErr {
    header: AconMessageHdr, // command = -Exxx, as defintion in Linux
    request: i32,           // original request code
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct AconGetReportReq {
    header: AconMessageHdr, // command = 0
    nonce: [u64; 2],
    data_type: i32, // 0 = no data; 1 = binary; 2 = string; others = reserved
}

#[repr(C)]
#[derive(Serialize, Debug, Clone, Copy)]
struct AconGetReportRsp {
    header: AconMessageHdr, // command = 1
    #[serde(with = "serde_arrays")]
    report: [u8; REPORT_SIZE],
    rtmr_count: i32,
    attestation_json_offset: i32,
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct AconSetAttestationDataReq {
    header: AconMessageHdr, // command = 2
    data_type: i32,         // Same definition as AconGetReportReq.dataType
}

#[repr(C)]
#[derive(Serialize, Debug, Clone, Copy)]
struct AconSetAttestationDataRsp {
    header: AconMessageHdr, // command = 3
}

#[allow(unused)]
union AconReq {
    header: AconMessageHdr,
    get_report: AconGetReportReq,
    set_attestation_data: AconSetAttestationDataReq,
}

#[allow(unused)]
union AconRsp {
    header: AconMessageHdr,
    error: AconMessageErr,
    get_report: AconGetReportRsp,
    set_attestation_data: AconSetAttestationDataRsp,
}

struct AconService {
    pod: Arc<RwLock<Pod>>,
}

impl AconService {
    async fn get_report(
        &self,
        uid: u32,
        nonce: [u64; 2],
        dtype: i32,
        data: String,
    ) -> Result<(i32, [u8; REPORT_SIZE], String)> {
        let ref_pod = self.pod.clone();
        let pod = ref_pod.read().await;

        let (requestor_nonce, acond_nonce) = utils::get_nounces(nonce[0], nonce[1])?;
        let attest_data = pod.get_attestation_data(
            requestor_nonce,
            acond_nonce,
            Some((uid, AttestDataValue::DataValue { dtype, data })),
        )?;
        let report = utils::get_report(&attest_data)?;

        Ok((NUM_RTMRS, report, attest_data))
    }

    async fn set_attestation_data(&self, uid: u32, dtype: i32, data: String) -> Result<()> {
        let ref_pod = self.pod.clone();
        let mut pod = ref_pod.write().await;

        let container = pod.get_container_mut(&uid).unwrap();
        container.attest_data = AttestDataValue::DataValue { dtype, data };

        Ok(())
    }
}

struct Request {
    command: i32,
    bytes: Vec<u8>,
    uid: u32,
    resp_tx: oneshot::Sender<Vec<u8>>,
}

pub unsafe fn convert_attest_data(end_with_nul: bool, data: &[u8]) -> &str {
    if end_with_nul {
        let end = data.iter().position(|&c| c == b'\0').unwrap_or(data.len());

        str::from_utf8_unchecked(&data[0..end])
    } else {
        str::from_utf8_unchecked(data)
    }
}

fn convert_error_bytes(command: i32, err: &str) -> Result<Vec<u8>> {
    let mut err_bytes = err.as_bytes().to_vec();

    let msg_err = AconMessageErr {
        header: AconMessageHdr {
            command: -1,
            size: err_bytes.len() as u32,
        },
        request: command,
    };

    let mut msg_err_bytes = bincode::serialize(&msg_err)?;
    msg_err_bytes.append(&mut err_bytes);

    Ok(msg_err_bytes)
}

async fn handle_request(stream: UnixStream, tx: mpsc::Sender<Request>) -> Result<()> {
    let mut resp_bytes: Option<Vec<u8>> = None;
    let mut msg_hdr: AconMessageHdr = AconMessageHdr::default();
    let mut msg_hdr_bytes = vec![0; mem::size_of::<AconMessageHdr>()];

    loop {
        stream.readable().await?;

        match stream.try_read(&mut msg_hdr_bytes) {
            Ok(n) => {
                if n != msg_hdr_bytes.len() {
                    resp_bytes = Some(utils::ERR_IPC_INVALID_REQ_FORMAT.as_bytes().to_vec());
                } else {
                    msg_hdr = bincode::deserialize(&msg_hdr_bytes)?;
                }
                break;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }

    if resp_bytes.is_none() {
        loop {
            let count = msg_hdr.size as usize - msg_hdr_bytes.len();
            let mut data = vec![0; count];

            match stream.try_read(&mut data) {
                Ok(n) => {
                    if n != data.len() {
                        resp_bytes = Some(utils::ERR_IPC_INVALID_REQ_FORMAT.as_bytes().to_vec());
                    } else {
                        msg_hdr_bytes.append(&mut data);
                    }
                    break;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    if resp_bytes.is_none() {
        let (resp_tx, resp_rx) = oneshot::channel();
        let request = Request {
            command: msg_hdr.command,
            bytes: msg_hdr_bytes,
            uid: stream.peer_cred()?.uid(),
            resp_tx,
        };

        let _ = tx.send(request).await;
        resp_bytes = Some(resp_rx.await?);
    }

    loop {
        stream.writable().await?;

        match stream.try_write(resp_bytes.as_ref().unwrap()) {
            Ok(_) => return Ok(()),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

async fn monitor_request(pod: Arc<RwLock<Pod>>, mut rx: mpsc::Receiver<Request>) -> Result<()> {
    let service = AconService { pod };

    loop {
        if let Some(request) = rx.recv().await {
            match dispatch_request(&request, &service).await {
                Ok(response) => {
                    let _ = request.resp_tx.send(response);
                }
                Err(e) => {
                    let err_bytes = convert_error_bytes(request.command, &e.to_string())?;
                    let _ = request.resp_tx.send(err_bytes);
                }
            }
        }
    }
}

async fn dispatch_request(request: &Request, service: &AconService) -> Result<Vec<u8>> {
    match request.command {
        0 => {
            let get_report_req: AconGetReportReq =
                bincode::deserialize(&request.bytes[0..mem::size_of::<AconGetReportReq>()])?;

            let attest_data_type = get_report_req.data_type;
            let attest_data = unsafe {
                convert_attest_data(
                    attest_data_type == 2,
                    &request.bytes[mem::size_of::<AconGetReportReq>()..],
                )
                .to_owned()
            };

            match service
                .get_report(
                    request.uid,
                    get_report_req.nonce,
                    attest_data_type,
                    attest_data,
                )
                .await
            {
                Ok((rtmr_count, report, data)) => {
                    let mut data_bytes = data.as_bytes().to_vec();
                    let get_report_resp = AconGetReportRsp {
                        header: AconMessageHdr {
                            command: request.command + 1,
                            size: (mem::size_of::<AconGetReportRsp>() + data_bytes.len()) as u32,
                        },
                        report,
                        rtmr_count,
                        attestation_json_offset: mem::size_of::<AconGetReportRsp>() as i32,
                    };

                    let mut resp_bytes = bincode::serialize(&get_report_resp)?;
                    resp_bytes.append(&mut data_bytes);

                    Ok(resp_bytes)
                }
                Err(e) => convert_error_bytes(request.command, &e.to_string()),
            }
        }

        2 => {
            let set_attestation_data_req: AconSetAttestationDataReq = bincode::deserialize(
                &request.bytes[0..mem::size_of::<AconSetAttestationDataReq>()],
            )?;

            let attest_data_type = set_attestation_data_req.data_type;
            let attest_data = unsafe {
                convert_attest_data(
                    attest_data_type == 2,
                    &request.bytes[mem::size_of::<AconSetAttestationDataReq>()..],
                )
                .to_owned()
            };

            if let Err(e) = service
                .set_attestation_data(request.uid, attest_data_type, attest_data)
                .await
            {
                convert_error_bytes(request.command, &e.to_string())
            } else {
                let set_attestation_data_rsp = AconSetAttestationDataRsp {
                    header: AconMessageHdr {
                        command: request.command + 1,
                        size: mem::size_of::<AconMessageHdr>() as u32,
                    },
                };

                Ok(bincode::serialize(&set_attestation_data_rsp)?)
            }
        }

        _ => Err(anyhow!(utils::ERR_IPC_NOT_SUPPORT_REQ)),
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

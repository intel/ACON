// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use anyhow::{anyhow, Result};
use nix::{ioctl_readwrite, ioctl_write_ptr};
use openssl::sha;
use std::{
    convert::TryInto,
    fs::File,
    marker::PhantomData,
    mem::{self, MaybeUninit},
    os::unix::io::AsRawFd,
};

pub const EXTEND_RTMR_DATA_SIZE: usize = 0x30;
pub const REPORT_DATA_SIZE: usize = 0x40;
pub const REPORT_SIZE: usize = 0x400;
pub const NUM_RTMRS: i32 = 4;

const TDX_GUEST: &str = "/dev/tdx_guest";
const HEADER_SIZE: usize = 4;
const REQ_BUF_SIZE: usize = 0x4000;
const GET_QUOTE_IN_FLIGHT: u64 = 0xffffffffffffffff;
const GET_QUOTE_SERVICE_UNAVAILABLE: u64 = 0x8000000000000001;

#[repr(C)]
pub struct __IncompleteArrayField<T>(PhantomData<T>, [T; 0]);

#[repr(C)]
pub struct TdxReportReq {
    report_data: [u8; REPORT_DATA_SIZE],
    td_report: [u8; REPORT_SIZE],
}

#[repr(C)]
pub struct TdxExtendRtmrReq {
    data: [u8; EXTEND_RTMR_DATA_SIZE],
    index: u8,
}

#[repr(C)]
struct TdxQuoteHdr {
    version: u64,
    status: u64,
    in_len: u32,
    out_len: u32,
    data: __IncompleteArrayField<u64>, // Same as defined - https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/tdx_attest
}

#[repr(C)]
pub struct TdxQuoteReq {
    buf: u64,
    len: u64,
}

ioctl_readwrite!(tdx_get_report, b'T', 0x01, TdxReportReq);
ioctl_write_ptr!(tdx_extend_rtmr, b'T', 0x03, TdxExtendRtmrReq);
ioctl_readwrite!(tdx_get_quote, b'T', 0x04, TdxQuoteReq);

pub fn extend_rtmr(contents: &str) -> Result<()> {
    let devf = match File::options().write(true).open(TDX_GUEST) {
        Ok(f) => Some(f),
        Err(_) => {
            eprintln!("Failed to open {}", TDX_GUEST);
            None
        }
    };

    if let Some(f) = devf {
        unsafe {
            let mut req = MaybeUninit::<TdxExtendRtmrReq>::uninit();
            (*req.as_mut_ptr()).data = sha::sha384(contents.to_string().as_bytes());
            (*req.as_mut_ptr()).index = 3;

            tdx_extend_rtmr(f.as_raw_fd(), req.as_mut_ptr())?;
        }
    }

    Ok(())
}

pub fn get_report(attest_data: &String) -> Result<Vec<u8>> {
    let devf = File::options().read(true).write(true).open(TDX_GUEST)?;

    let hash = sha::sha384(attest_data.as_bytes());
    let mut report_data = vec![0; REPORT_DATA_SIZE];
    for i in 0..hash.len() {
        report_data[i] = hash[i];
    }

    unsafe {
        let mut req = MaybeUninit::<TdxReportReq>::uninit();
        let data = report_data.try_into().unwrap();
        (*req.as_mut_ptr()).report_data.clone_from(&data);

        tdx_get_report(devf.as_raw_fd(), req.as_mut_ptr())?;

        Ok((*req.as_mut_ptr()).td_report.to_vec())
    }
}

pub fn get_quote(attest_data: &String) -> Result<Vec<u8>> {
    let report = get_report(attest_data)?;

    let devf = File::options().read(true).write(true).open(TDX_GUEST)?;

    let (err, req) = qgs_msg_lib::qgs_msg_gen_get_quote_req(report.as_slice(), None);
    if err != qgs_msg_lib::QGS_MSG_SUCCESS {
        return Err(anyhow!(utils::ERR_ATTEST_UNEXPECTED));
    }

    let request = req.unwrap();
    if request.len() > REQ_BUF_SIZE - HEADER_SIZE - mem::size_of::<TdxQuoteHdr>() {
        return Err(anyhow!(utils::ERR_ATTEST_NOT_SUPPORTED));
    }

    let request_size = request.len() as u32;
    let mut buf = vec![0u8; REQ_BUF_SIZE];
    let tdx_quote_hdr = buf.as_mut_ptr() as *mut TdxQuoteHdr;

    unsafe {
        (*tdx_quote_hdr).version = 1;
        (*tdx_quote_hdr).status = 0;
        (*tdx_quote_hdr).in_len = HEADER_SIZE as u32 + request_size;
        (*tdx_quote_hdr).out_len = 0;

        let mut data_index = mem::size_of::<TdxQuoteHdr>();
        for i in 0..HEADER_SIZE {
            buf[data_index + i] = ((request_size >> (HEADER_SIZE - 1 - i) * 8) & 0xFF) as u8;
        }
        data_index += HEADER_SIZE;
        for i in 0..request.len() {
            buf[data_index + i] = request[i];
        }

        let mut req = MaybeUninit::<TdxQuoteReq>::uninit();
        (*req.as_mut_ptr()).buf = tdx_quote_hdr as u64;
        (*req.as_mut_ptr()).len = REQ_BUF_SIZE as u64;

        tdx_get_quote(devf.as_raw_fd(), req.as_mut_ptr())?;

        if (*tdx_quote_hdr).status != 0 || (*tdx_quote_hdr).out_len < HEADER_SIZE as u32 {
            match (*tdx_quote_hdr).status {
                GET_QUOTE_IN_FLIGHT => return Err(anyhow!(utils::ERR_ATTEST_BUSY)),
                GET_QUOTE_SERVICE_UNAVAILABLE => {
                    return Err(anyhow!(utils::ERR_ATTEST_NOT_SUPPORTED))
                }
                _ => return Err(anyhow!(utils::ERR_ATTEST_UNEXPECTED)),
            }
        }

        let mut msg_size: u32 = 0;
        for i in 0..HEADER_SIZE {
            msg_size = msg_size * 256 + (buf[mem::size_of::<TdxQuoteHdr>() + i] & 0xFF) as u32;
        }
        if msg_size != (*tdx_quote_hdr).out_len - HEADER_SIZE as u32 {
            return Err(anyhow!(utils::ERR_ATTEST_UNEXPECTED));
        }

        let (err, quote, _) = qgs_msg_lib::qgs_msg_inflate_get_quote_resp(
            &buf[data_index..data_index + msg_size as usize],
        );
        if err != qgs_msg_lib::QGS_MSG_SUCCESS {
            return Err(anyhow!(utils::ERR_ATTEST_UNEXPECTED));
        }

        Ok(quote.unwrap())
    }
}

mod qgs_msg_lib {
    use super::__IncompleteArrayField;
    use std::mem;

    pub const QGS_MSG_SUCCESS: u32 = 0x0000; // Success
    #[allow(dead_code)]
    pub const QGS_MSG_ERROR_UNEXPECTED: u32 = 0x00012001; // Unexpected error
    #[allow(dead_code)]
    pub const QGS_MSG_ERROR_OUT_OF_MEMORY: u32 = 0x00012002; // Not enough memory is available to complete this operation
    pub const QGS_MSG_ERROR_INVALID_PARAMETER: u32 = 0x00012003; // The parameter is incorrect
    pub const QGS_MSG_ERROR_INVALID_VERSION: u32 = 0x00012004; // Unrecognized version of serialized data
    pub const QGS_MSG_ERROR_INVALID_TYPE: u32 = 0x00012005; // Invalid message type found
    pub const QGS_MSG_ERROR_INVALID_SIZE: u32 = 0x00012006; // Invalid message size found
    pub const QGS_MSG_ERROR_INVALID_CODE: u32 = 0x00012007; // Invalid error code
    pub const QGS_MSG_ERROR_MAX: u32 = 0x00012008; // Indicate max error to allow better translation.

    const QGS_MSG_LIB_MAJOR_VER: u16 = 1;
    const QGS_MSG_LIB_MINOR_VER: u16 = 0;
    const QGS_MSG_GET_QUOTE_REQ: u32 = 0;
    const QGS_MSG_GET_QUOTE_RESP: u32 = 1;

    #[repr(C)]
    struct QgsMsgHeader {
        major_version: u16,
        minor_version: u16,
        header_type: u32,
        size: u32,
        error_code: u32,
    }

    #[repr(C)]
    struct QgsMsgGetQuoteReq {
        header: QgsMsgHeader,                       // header.type = GET_QUOTE_REQ
        report_size: u32,                           // cannot be 0
        id_list_size: u32,                          // length of id_list, in byte, can be 0
        report_id_list: __IncompleteArrayField<u8>, // report followed by id list
    }

    #[repr(C)]
    struct QgsMsgGetQuoteResp {
        header: QgsMsgHeader,                 // header.type = GET_QUOTE_RESP
        selected_id_size: u32,                // can be 0 in case only one id is sent in request
        quote_size: u32,                      // length of quote_data, in byte
        id_quote: __IncompleteArrayField<u8>, // selected id followed by quote
    }

    pub fn qgs_msg_gen_get_quote_req(
        report: &[u8],
        id_list: Option<&[u8]>,
    ) -> (u32, Option<Vec<u8>>) {
        if report.len() != super::REPORT_SIZE {
            return (QGS_MSG_ERROR_INVALID_PARAMETER, None);
        }

        if id_list.is_some() && id_list.unwrap().len() == 0 {
            return (QGS_MSG_ERROR_INVALID_PARAMETER, None);
        }

        let report_size = report.len() as u32;
        let id_list_size = if let Some(list) = id_list {
            list.len() as u32
        } else {
            0
        };

        let mut buf_size = mem::size_of::<QgsMsgGetQuoteReq>() as u32;
        buf_size += report_size;
        buf_size += id_list_size;

        let mut buf = vec![0u8; buf_size as usize];
        let qgs_msg_get_quote_req = buf.as_mut_ptr() as *mut QgsMsgGetQuoteReq;
        unsafe {
            (*qgs_msg_get_quote_req).header.major_version = QGS_MSG_LIB_MAJOR_VER;
            (*qgs_msg_get_quote_req).header.minor_version = QGS_MSG_LIB_MINOR_VER;
            (*qgs_msg_get_quote_req).header.header_type = QGS_MSG_GET_QUOTE_REQ;
            (*qgs_msg_get_quote_req).header.size = buf_size;
            (*qgs_msg_get_quote_req).header.error_code = 0;
            (*qgs_msg_get_quote_req).report_size = report_size;
            (*qgs_msg_get_quote_req).id_list_size = id_list_size;

            let mut report_id_list_index = mem::size_of::<QgsMsgGetQuoteReq>();
            for i in 0..report_size as usize {
                buf[report_id_list_index + i] = report[i];
            }
            report_id_list_index += report_size as usize;
            if let Some(list) = id_list {
                for i in 0..list.len() {
                    buf[report_id_list_index + i] = list[i];
                }
            }
        }

        return (QGS_MSG_SUCCESS, Some(buf));
    }

    pub fn qgs_msg_inflate_get_quote_resp(
        serialized_resp: &[u8],
    ) -> (u32, Option<Vec<u8>>, Option<Vec<u8>>) {
        if serialized_resp.len() < mem::size_of::<QgsMsgGetQuoteResp>() {
            return (QGS_MSG_ERROR_INVALID_PARAMETER, None, None);
        }

        let qgs_msg_get_quote_resp = serialized_resp.as_ptr() as *const QgsMsgGetQuoteResp;
        unsafe {
            if (*qgs_msg_get_quote_resp).header.major_version != QGS_MSG_LIB_MAJOR_VER {
                return (QGS_MSG_ERROR_INVALID_VERSION, None, None);
            }
            if (*qgs_msg_get_quote_resp).header.header_type != QGS_MSG_GET_QUOTE_RESP {
                return (QGS_MSG_ERROR_INVALID_TYPE, None, None);
            }
            if (*qgs_msg_get_quote_resp).header.size != serialized_resp.len() as u32 {
                return (QGS_MSG_ERROR_INVALID_SIZE, None, None);
            }

            let mut size = mem::size_of::<QgsMsgGetQuoteResp>() as u32;
            size += (*qgs_msg_get_quote_resp).selected_id_size;
            size += (*qgs_msg_get_quote_resp).quote_size;

            if (*qgs_msg_get_quote_resp).header.size != size {
                return (QGS_MSG_ERROR_INVALID_SIZE, None, None);
            }

            if (*qgs_msg_get_quote_resp).header.error_code == QGS_MSG_SUCCESS {
                if (*qgs_msg_get_quote_resp).quote_size == 0 {
                    return (QGS_MSG_ERROR_INVALID_SIZE, None, None);
                }

                let mut id_quote_index = mem::size_of::<QgsMsgGetQuoteResp>();
                let quote = serialized_resp[id_quote_index
                    ..id_quote_index + (*qgs_msg_get_quote_resp).quote_size as usize]
                    .to_vec();
                id_quote_index += (*qgs_msg_get_quote_resp).quote_size as usize;
                let selected_id = if (*qgs_msg_get_quote_resp).selected_id_size != 0 {
                    Some(serialized_resp[id_quote_index..].to_vec())
                } else {
                    None
                };

                return (QGS_MSG_SUCCESS, Some(quote), selected_id);
            } else if (*qgs_msg_get_quote_resp).header.error_code < QGS_MSG_ERROR_MAX {
                return (QGS_MSG_ERROR_INVALID_SIZE, None, None);
            } else {
                return (QGS_MSG_ERROR_INVALID_CODE, None, None);
            }
        }
    }
}

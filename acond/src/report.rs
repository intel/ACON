// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use anyhow::{anyhow, Result};
use nix::{ioctl_read, ioctl_readwrite};
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

const TDX_GUEST: &str = "/dev/tdx_guest";
const REQ_BUF_SIZE: usize = 0x4000;

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

#[repr(packed)]
struct TdxQuoteSubHdr {
    size: u32,
    _data: __IncompleteArrayField<u64>,
}

#[repr(packed)]
struct TdxQuoteHdr {
    version: u64,
    status: u64,
    in_len: u32,
    out_len: u32,
    sub_hdr: TdxQuoteSubHdr,
}

#[repr(C)]
pub struct TdxQuoteReq {
    buf: u64,
    len: u64,
}

ioctl_readwrite!(tdx_get_report, b'T', 0x01, TdxReportReq);
ioctl_read!(tdx_extend_rtmr, b'T', 0x03, TdxExtendRtmrReq);
ioctl_read!(tdx_get_quote, b'T', 0x04, TdxQuoteReq);

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
    report_data[..hash.len()].copy_from_slice(&hash[..]);

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

    let request = qgs_msg::create_get_quote_req(report.as_slice(), None)
        .map_err(|_| anyhow!(utils::ERR_UNEXPECTED))?;
    if request.len() > REQ_BUF_SIZE - mem::size_of::<TdxQuoteHdr>() {
        return Err(anyhow!(utils::ERR_ATTEST_NOT_SUPPORTED));
    }

    let header_size = mem::size_of::<TdxQuoteSubHdr>() as u32;
    let request_size = request.len() as u32;
    let mut buf = vec![0u8; REQ_BUF_SIZE];
    let tdx_quote_hdr = buf.as_mut_ptr() as *mut TdxQuoteHdr;

    unsafe {
        (*tdx_quote_hdr).version = 1;
        (*tdx_quote_hdr).status = 0;
        (*tdx_quote_hdr).in_len = header_size + request_size;
        (*tdx_quote_hdr).out_len = 0;
        (*tdx_quote_hdr).sub_hdr.size = request_size.to_be();

        let data_offset = mem::size_of::<TdxQuoteHdr>();
        buf[data_offset..(data_offset + request.len())].copy_from_slice(&request[..]);

        let mut req = MaybeUninit::<TdxQuoteReq>::uninit();
        (*req.as_mut_ptr()).buf = tdx_quote_hdr as u64;
        (*req.as_mut_ptr()).len = REQ_BUF_SIZE as u64;

        tdx_get_quote(devf.as_raw_fd(), req.as_mut_ptr())?;

        if (*tdx_quote_hdr).status != 0 || (*tdx_quote_hdr).out_len < header_size {
            return Err(anyhow!(utils::ERR_UNEXPECTED));
        }

        (*tdx_quote_hdr).sub_hdr.size = (*tdx_quote_hdr).sub_hdr.size.to_be();
        if (*tdx_quote_hdr).sub_hdr.size != (*tdx_quote_hdr).out_len - header_size {
            return Err(anyhow!(utils::ERR_UNEXPECTED));
        }

        let (quote, _) = qgs_msg::inflate_get_quote_resp(
            &buf[data_offset..data_offset + (*tdx_quote_hdr).sub_hdr.size as usize],
        )
        .map_err(|_| anyhow!(utils::ERR_UNEXPECTED))?;

        Ok(quote)
    }
}

mod qgs_msg {
    use super::__IncompleteArrayField;
    use std::mem;

    const MAJOR_VER: u16 = 1;
    const MINOR_VER: u16 = 0;
    const GET_QUOTE_REQ: u32 = 0;
    const GET_QUOTE_RESP: u32 = 1;

    #[rustfmt::skip]
    #[allow(dead_code)]
    pub enum MessageStatus {
        Success,               // Success
        ErrorUnexpected,       // Unexpected error
        ErrorOutOfmemory,      // Not enough memory is available to complete this operation
        ErrorInvalidParameter, // The parameter is incorrect
        ErrorInvalidVersion,   // Unrecognized version of serialized data
        ErrorInvalidType,      // Invalid message type found
        ErrorInvalidSize,      // Invalid message size found
        ErrorInvalidCode,      // Invalid error code
        ErrorMax,              // Indicate max error to allow better translation.
    }

    impl MessageStatus {
        #[rustfmt::skip]
        fn value(&self) -> u32 {
            match self {
                MessageStatus::Success               => 0x0,
                MessageStatus::ErrorUnexpected       => 0x00012001,
                MessageStatus::ErrorOutOfmemory      => 0x00012002,
                MessageStatus::ErrorInvalidParameter => 0x00012003,
                MessageStatus::ErrorInvalidVersion   => 0x00012004,
                MessageStatus::ErrorInvalidType      => 0x00012005,
                MessageStatus::ErrorInvalidSize      => 0x00012006,
                MessageStatus::ErrorInvalidCode      => 0x00012007,
                MessageStatus::ErrorMax              => 0x00012008,
            }
        }
    }

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

    pub fn create_get_quote_req(
        report: &[u8],
        id_list: Option<&[u8]>,
    ) -> Result<Vec<u8>, MessageStatus> {
        if report.len() != super::REPORT_SIZE {
            return Err(MessageStatus::ErrorInvalidParameter);
        }

        if id_list.is_some() && id_list.unwrap().is_empty() {
            return Err(MessageStatus::ErrorInvalidParameter);
        }

        let report_size = report.len();
        let id_list_size = id_list.map_or(0, |list| list.len());

        let mut buf_size = mem::size_of::<QgsMsgGetQuoteReq>();
        buf_size += report_size;
        buf_size += id_list_size;

        let mut buf = vec![0u8; buf_size];
        let get_quote_req = buf.as_mut_ptr() as *mut QgsMsgGetQuoteReq;
        unsafe {
            (*get_quote_req).header.major_version = MAJOR_VER;
            (*get_quote_req).header.minor_version = MINOR_VER;
            (*get_quote_req).header.header_type = GET_QUOTE_REQ;
            (*get_quote_req).header.size = buf_size as u32;
            (*get_quote_req).header.error_code = 0;
            (*get_quote_req).report_size = report_size as u32;
            (*get_quote_req).id_list_size = id_list_size as u32;

            let mut offset = mem::size_of::<QgsMsgGetQuoteReq>();
            buf[offset..(offset + report_size)].copy_from_slice(&report[..report_size]);

            if let Some(list) = id_list {
                offset += report_size;
                buf[offset..(offset + list.len())].copy_from_slice(list);
            }
        }

        Ok(buf)
    }

    pub fn inflate_get_quote_resp(
        serialized_resp: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), MessageStatus> {
        if serialized_resp.len() < mem::size_of::<QgsMsgGetQuoteResp>() {
            return Err(MessageStatus::ErrorInvalidParameter);
        }

        let get_quote_resp = serialized_resp.as_ptr() as *const QgsMsgGetQuoteResp;
        unsafe {
            if (*get_quote_resp).header.major_version != MAJOR_VER {
                return Err(MessageStatus::ErrorInvalidVersion);
            }
            if (*get_quote_resp).header.header_type != GET_QUOTE_RESP {
                return Err(MessageStatus::ErrorInvalidType);
            }
            if (*get_quote_resp).header.size != serialized_resp.len() as u32 {
                return Err(MessageStatus::ErrorInvalidSize);
            }

            let mut size = mem::size_of::<QgsMsgGetQuoteResp>() as u32;
            size += (*get_quote_resp).selected_id_size;
            size += (*get_quote_resp).quote_size;

            if (*get_quote_resp).header.size != size {
                return Err(MessageStatus::ErrorInvalidSize);
            }

            if (*get_quote_resp).header.error_code == MessageStatus::Success.value() {
                if (*get_quote_resp).quote_size == 0 {
                    return Err(MessageStatus::ErrorInvalidSize);
                }

                let mut offset = mem::size_of::<QgsMsgGetQuoteResp>();
                let quote = serialized_resp[offset..offset + (*get_quote_resp).quote_size as usize]
                    .to_vec();

                let selected_id = match (*get_quote_resp).selected_id_size {
                    0 => None,
                    _ => {
                        offset += (*get_quote_resp).quote_size as usize;
                        Some(serialized_resp[offset..].to_vec())
                    }
                };

                Ok((quote, selected_id))
            } else if (*get_quote_resp).header.error_code < MessageStatus::ErrorMax.value() {
                Err(MessageStatus::ErrorInvalidSize)
            } else {
                Err(MessageStatus::ErrorInvalidCode)
            }
        }
    }
}

// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use anyhow::{anyhow, Result};
use nix::{errno::Errno, unistd};
use std::{marker::Unpin, mem, os::unix::io::RawFd, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

pub async fn read_async_lock<R>(reader: Arc<Mutex<R>>) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf: Vec<u8> = vec![0; utils::BUFF_SIZE];
    let mut offset: usize = 0;

    let mut reader = reader.lock().await;
    loop {
        match reader.read(&mut buf[offset..]).await {
            Ok(n) => {
                offset += n;
                if offset == buf.len() {
                    buf.resize(buf.len() + utils::BUFF_SIZE, 0);
                } else {
                    buf.truncate(offset);
                    return Ok(buf);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

pub async fn write_async_lock<W>(writer: Arc<Mutex<W>>, buf: &[u8], len: usize) -> Result<usize>
where
    W: AsyncWriteExt + Unpin,
{
    let mut offset: usize = 0;

    let mut writer = writer.lock().await;
    loop {
        match writer.write(&buf[offset..]).await {
            Ok(n) => {
                offset += n;
                if offset == len {
                    return Ok(len);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

pub async fn read_async_struct<R, S>(reader: &mut R) -> Result<(S, Vec<u8>)>
where
    R: AsyncReadExt + Unpin,
    S: Copy,
{
    let buf_size = mem::size_of::<S>();
    let buf = read_async_with_size(reader, buf_size).await?;
    if buf.len() != buf_size {
        return Err(anyhow!(utils::ERR_UNEXPECTED));
    }

    let (_, body, _) = unsafe { buf.align_to::<S>() };
    Ok((body[0], buf))
}

pub async fn read_async_with_size<R>(reader: &mut R, len: usize) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf = vec![0u8; len];
    let mut offset = 0;

    loop {
        match reader.read(&mut buf[offset..]).await {
            Ok(0) => {
                buf.truncate(offset);
                return Ok(buf);
            }
            Ok(n) => {
                offset += n;
                if offset == len {
                    return Ok(buf);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[allow(dead_code)]
pub async fn read_async<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf: Vec<u8> = vec![0; utils::BUFF_SIZE];
    let mut offset: usize = 0;

    loop {
        match reader.read(&mut buf[offset..]).await {
            Ok(n) => {
                offset += n;
                if offset == buf.len() {
                    buf.resize(buf.len() + utils::BUFF_SIZE, 0);
                } else {
                    buf.truncate(offset);
                    return Ok(buf);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

pub async fn write_async<W>(writer: &mut W, buf: &[u8], len: usize) -> Result<usize>
where
    W: AsyncWriteExt + Unpin,
{
    let mut offset: usize = 0;

    loop {
        match writer.write(&buf[offset..]).await {
            Ok(n) => {
                offset += n;
                if offset == len {
                    return Ok(len);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[allow(dead_code)]
pub fn read(fd: RawFd) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = vec![0; utils::BUFF_SIZE];
    let mut offset = 0;

    loop {
        match unistd::read(fd, &mut buf[offset..]) {
            Ok(n) => {
                offset += n;
                if offset == buf.len() {
                    buf.resize(buf.len() + utils::BUFF_SIZE, 0);
                } else {
                    buf.truncate(offset);
                    return Ok(buf);
                }
            }
            Err(Errno::EAGAIN) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

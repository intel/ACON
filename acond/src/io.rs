// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use anyhow::Result;
use nix::{errno::Errno, unistd};
use std::{io::ErrorKind, marker::Unpin, os::unix::io::RawFd, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

pub async fn read_async_lock<R>(reader: Arc<Mutex<R>>) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf: Vec<u8> = vec![0; utils::BUFF_SIZE];
    let mut len = 0;

    let mut reader = reader.lock().await;
    loop {
        match reader.read(&mut buf[len..]).await {
            Ok(l) => {
                len += l;
                if len == buf.len() {
                    buf.resize(buf.len() + utils::BUFF_SIZE, 0);
                } else {
                    buf.truncate(len);
                    return Ok(buf);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

pub async fn write_async_lock<W>(writer: Arc<Mutex<W>>, buf: &[u8]) -> Result<usize>
where
    W: AsyncWriteExt + Unpin,
{
    let mut writer = writer.lock().await;
    loop {
        match writer.write(buf).await {
            Ok(n) => return Ok(n),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
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
    let mut len = 0;

    loop {
        match reader.read(&mut buf[len..]).await {
            Ok(l) => {
                len += l;
                if len == buf.len() {
                    buf.resize(buf.len() + utils::BUFF_SIZE, 0);
                } else {
                    buf.truncate(len);
                    return Ok(buf);
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

pub async fn read_async_with_size<R>(reader: &mut R, len: usize) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf = vec![0u8; len];

    loop {
        match reader.read(&mut buf).await {
            Ok(n) => {
                if n != len {
                    buf.truncate(n)
                }
                return Ok(buf);
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

pub async fn write_async<W>(writer: &mut W, buf: &[u8]) -> Result<usize>
where
    W: AsyncWriteExt + Unpin,
{
    loop {
        match writer.write(buf).await {
            Ok(n) => return Ok(n),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

#[allow(dead_code)]
pub fn read(fd: RawFd) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = vec![0; utils::BUFF_SIZE];
    let mut len = 0;

    loop {
        match unistd::read(fd, &mut buf[len..]) {
            Ok(l) => {
                len += l;
                if len == buf.len() {
                    buf.resize(buf.len() + utils::BUFF_SIZE, 0);
                } else {
                    buf.truncate(len);
                    break;
                }
            }
            Err(Errno::EAGAIN) => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(buf)
}

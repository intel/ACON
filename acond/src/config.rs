// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use anyhow::{anyhow, Result};
use std::fs;

const KERNEL_CMDLINE: &str = "/proc/cmdline";
const KEY_VSOCK_CONN: &str = "acond.vsock_conn";
const KEY_VSOCK_PORT: &str = "acond.vsock_port";
const KEY_TCP_PORT: &str = "acond.tcp_port";
const KEY_TIMEOUT: &str = "acond.timeout";
const KEY_OPENID_USER: &str = "acond.openid_user";
const KEY_HTTPS_PROXY: &str = "acond.https_proxy";
const DEF_VSOCK_PORT: u32 = 1024;
const DEF_TCP_PORT: u32 = 1025;
const DEF_TIMEOUT: u32 = 180;

#[derive(Debug)]
pub struct Config {
    pub vsock_conn: bool,
    pub vsock_port: u32,
    pub tcp_port: u32,
    pub timeout: u32,
    pub openid_user: Option<String>,
    pub https_proxy: Option<String>,
}

impl Config {
    pub fn new() -> Config {
        Config {
            vsock_conn: false,
            vsock_port: DEF_VSOCK_PORT,
            tcp_port: DEF_TCP_PORT,
            timeout: DEF_TIMEOUT,
            openid_user: None,
            https_proxy: None,
        }
    }

    pub fn parse_cmdline(&mut self, file: Option<&str>) -> Result<()> {
        let f = file.unwrap_or(KERNEL_CMDLINE);
        let cmdline = fs::read_to_string(f)?;
        let params = cmdline.split_ascii_whitespace();

        for param in params {
            let mut parts = param.splitn(2, '=');
            let key = parts.next();
            let value = parts.next();

            match key {
                Some(KEY_VSOCK_CONN) if value.is_none() => self.vsock_conn = true,
                Some(KEY_VSOCK_PORT) => {
                    self.vsock_port = value
                        .ok_or_else(|| anyhow!(utils::ERR_CFG_INVALID_VSOCK_PORT))?
                        .parse::<u32>()
                        .map_err(|_| anyhow!(utils::ERR_CFG_INVALID_VSOCK_PORT))?
                }
                Some(KEY_TCP_PORT) => {
                    self.tcp_port = value
                        .ok_or_else(|| anyhow!(utils::ERR_CFG_INVALID_TCPIP_PORT))?
                        .parse::<u32>()
                        .map_err(|_| anyhow!(utils::ERR_CFG_INVALID_TCPIP_PORT))?
                }
                Some(KEY_TIMEOUT) => {
                    self.timeout = value
                        .ok_or_else(|| anyhow!(utils::ERR_CFG_INVALID_TIMEOUT))?
                        .parse::<u32>()
                        .map_err(|_| anyhow!(utils::ERR_CFG_INVALID_TIMEOUT))?
                }
                Some(KEY_OPENID_USER) => self.openid_user = value.map(|s| s.into()),
                Some(KEY_HTTPS_PROXY) => self.https_proxy = value.map(|s| s.into()),
                _ => (),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod unit_test {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    const VAL_VSOCK_PORT: u32 = 8888;
    const VAL_TIMEOUT: u32 = 100;

    #[test]
    fn test_new() {
        let conf = Config::new();
        assert_eq!(conf.vsock_port, DEF_VSOCK_PORT);
        assert_eq!(conf.timeout, DEF_TIMEOUT);
    }

    #[test]
    fn test_parse_cmdline() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmpfile = tmpdir.path().join("cmdline");

        {
            // No parameters
            File::create(&tmpfile).unwrap();

            let mut conf = Config::new();
            conf.parse_cmdline(tmpfile.to_str()).unwrap();
            assert_eq!(conf.vsock_port, DEF_VSOCK_PORT);
            assert_eq!(conf.timeout, DEF_TIMEOUT);
        }

        {
            // Only include vsock port number in the parameters
            let mut file = File::create(&tmpfile).unwrap();
            write!(file, "{}={}", KEY_VSOCK_PORT, VAL_VSOCK_PORT).unwrap();

            let mut conf = Config::new();
            conf.parse_cmdline(tmpfile.to_str()).unwrap();
            assert_eq!(conf.vsock_port, VAL_VSOCK_PORT);
            assert_eq!(conf.timeout, DEF_TIMEOUT);
        }

        {
            // Only include timeout in the parameters
            let mut file = File::create(&tmpfile).unwrap();
            write!(file, "{}={}", KEY_TIMEOUT, VAL_TIMEOUT).unwrap();

            let mut conf = Config::new();
            conf.parse_cmdline(tmpfile.to_str()).unwrap();
            assert_eq!(conf.vsock_port, DEF_VSOCK_PORT);
            assert_eq!(conf.timeout, VAL_TIMEOUT);
        }

        {
            // Include vsock port number/timeout in the parameters
            let mut file = File::create(&tmpfile).unwrap();
            write!(
                file,
                "{}={} {}={}",
                KEY_VSOCK_PORT, VAL_VSOCK_PORT, KEY_TIMEOUT, VAL_TIMEOUT
            )
            .unwrap();

            let mut conf = Config::new();
            conf.parse_cmdline(tmpfile.to_str()).unwrap();
            assert_eq!(conf.vsock_port, VAL_VSOCK_PORT);
            assert_eq!(conf.timeout, VAL_TIMEOUT);
        }

        {
            // Invalid parameters - vsock port number
            let mut file = File::create(&tmpfile).unwrap();
            write!(file, "{}={}=1", KEY_VSOCK_PORT, VAL_VSOCK_PORT).unwrap();

            let mut conf = Config::new();
            let ret = conf.parse_cmdline(tmpfile.to_str());
            assert!(ret.is_err());
        }

        {
            // Invalid parameters - vsock port number
            let mut file = File::create(&tmpfile).unwrap();
            write!(file, "{}=xxx", KEY_VSOCK_PORT).unwrap();

            let mut conf = Config::new();
            let ret = conf.parse_cmdline(tmpfile.to_str());
            assert!(ret.is_err());
        }

        {
            // Invalid parameters - timeout
            let mut file = File::create(&tmpfile).unwrap();
            write!(file, "{}={}=", KEY_TIMEOUT, VAL_TIMEOUT).unwrap();

            let mut conf = Config::new();
            let ret = conf.parse_cmdline(tmpfile.to_str());
            assert!(ret.is_err());
        }

        {
            // Invalid parameters - timeout
            let mut file = File::create(&tmpfile).unwrap();
            write!(file, "{}=xxx", KEY_TIMEOUT).unwrap();

            let mut conf = Config::new();
            let ret = conf.parse_cmdline(tmpfile.to_str());
            assert!(ret.is_err());
        }
    }
}

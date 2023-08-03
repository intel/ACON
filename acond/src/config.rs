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
const DEF_VSOCK_PORT: u32 = 1024;
const DEF_TCP_PORT: u32 = 1025;
const DEF_TIMEOUT: u32 = 180;

#[derive(Debug)]
pub struct Config {
    pub vsock_conn: bool,
    pub vsock_port: u32,
    pub tcp_port: u32,
    pub timeout: u32,
}

impl Config {
    pub fn new() -> Config {
        Config {
            vsock_conn: false,
            vsock_port: DEF_VSOCK_PORT,
            tcp_port: DEF_TCP_PORT,
            timeout: DEF_TIMEOUT,
        }
    }

    pub fn parse_cmdline(&mut self, file: Option<&str>) -> Result<()> {
        let f = file.unwrap_or(KERNEL_CMDLINE);
        let cmdline = fs::read_to_string(f)?;
        let params = cmdline.split_ascii_whitespace();
        for param in params {
            if param.starts_with(KEY_VSOCK_CONN.to_string().as_str()) {
                self.vsock_conn = true;
            } else if param.starts_with(format!("{}=", KEY_VSOCK_PORT).as_str()) {
                let fields = param.split('=').collect::<Vec<_>>();
                if fields.len() != 2 {
                    return Err(anyhow!(utils::ERR_CFG_INVALID_VSOCK_PORT));
                }

                self.vsock_port = fields[1].parse::<u32>()?;
            } else if param.starts_with(format!("{}=", KEY_TCP_PORT).as_str()) {
                let fields = param.split('=').collect::<Vec<_>>();
                if fields.len() != 2 {
                    return Err(anyhow!(utils::ERR_CFG_INVALID_TCPIP_PORT));
                }

                self.tcp_port = fields[1].parse::<u32>()?;
            } else if param.starts_with(format!("{}=", KEY_TIMEOUT).as_str()) {
                let fields = param.split('=').collect::<Vec<_>>();
                if fields.len() != 2 {
                    return Err(anyhow!(utils::ERR_CFG_INVALID_TIMEOUT));
                }

                self.timeout = fields[1].parse::<u32>()?;
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

// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::utils;
use anyhow::{anyhow, Result};
use nix::{
    errno::Errno,
    libc, pty,
    sys::{
        select::{self, FdSet},
        termios::{self, LocalFlags, SetArg, Termios},
    },
    unistd::{self, ForkResult},
};
use rustyline::{error::ReadlineError, Editor};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    io::{self as stdio, Write},
    os::unix::io::{FromRawFd, RawFd},
    path::PathBuf,
    process, str,
    sync::Arc,
};
use tokio::{
    fs::File,
    io::{self, AsyncReadExt},
    sync::{mpsc, oneshot, Mutex},
};

lazy_static! {
    static ref TERMINAL_LIST: Arc<Mutex<TerminalList>> = Arc::new(Mutex::new(TerminalList::new()));
}

pub enum Command {
    Enter {
        master: RawFd,
        resp: oneshot::Sender<Option<Vec<u8>>>,
    },
    Leave {
        resp: oneshot::Sender<bool>,
    },
    List {
        resp: oneshot::Sender<Vec<RawFd>>,
    },
}

#[derive(Debug, Clone)]
struct TerminalSetting {
    def_term_setting: Termios,
    raw_term_setting: Termios,
}

#[derive(Debug)]
struct Terminal {
    active: bool,
    prompt: Option<Vec<u8>>,
}

#[derive(Debug)]
struct TerminalList {
    terminals: BTreeMap<RawFd, Terminal>,
    term_setting: TerminalSetting,
}

impl TerminalSetting {
    pub fn new() -> Self {
        let mut def_term_setting = termios::tcgetattr(libc::STDIN_FILENO).unwrap();
        if def_term_setting.local_flags & LocalFlags::ICANON == LocalFlags::empty() {
            def_term_setting.local_flags |= LocalFlags::ICANON;
        }

        let mut raw_term_setting = def_term_setting.clone();
        termios::cfmakeraw(&mut raw_term_setting);

        Self {
            def_term_setting,
            raw_term_setting,
        }
    }

    pub fn enter_terminal(&self) -> Result<()> {
        termios::tcsetattr(
            libc::STDIN_FILENO,
            SetArg::TCSAFLUSH,
            &self.raw_term_setting,
        )?;

        Ok(())
    }

    pub fn leave_terminal(&self) -> Result<()> {
        termios::tcsetattr(
            libc::STDIN_FILENO,
            SetArg::TCSAFLUSH,
            &self.def_term_setting,
        )?;

        Ok(())
    }
}

impl Terminal {
    pub fn new() -> Self {
        Self {
            active: false,
            prompt: None,
        }
    }

    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    pub fn set_prompt(&mut self, prompt: Vec<u8>) {
        if !prompt.is_empty() {
            self.prompt = Some(prompt);
        }
    }
}

impl TerminalList {
    pub fn new() -> Self {
        Self {
            terminals: BTreeMap::new(),
            term_setting: TerminalSetting::new(),
        }
    }

    pub fn add_terminal(&mut self, master: RawFd) {
        self.terminals.insert(master, Terminal::new());
    }

    pub fn remove_terminal(&mut self, master: RawFd) -> Result<()> {
        if let Some(terminal) = self.terminals.remove(&master) {
            if terminal.active {
                self.leave_terminal()?;
            }
        }

        Ok(())
    }

    pub fn enter_terminal(&mut self, master: RawFd) -> Option<&Terminal> {
        if let Some(terminal) = self.terminals.get_mut(&master) {
            if self.term_setting.enter_terminal().is_err() {
                return None;
            }

            terminal.set_active(true);
            return Some(terminal);
        }

        None
    }

    pub fn leave_terminal(&mut self) -> Result<()> {
        self.term_setting.leave_terminal()?;
        for (_, terminal) in self.terminals.iter_mut() {
            terminal.set_active(false);
        }

        Ok(())
    }
}

pub async fn run_terminal_server(mut rx: mpsc::Receiver<Command>) -> Result<()> {
    while let Some(cmd) = rx.recv().await {
        let ref_terminal_list = TERMINAL_LIST.clone();
        let mut terminal_list = ref_terminal_list.lock().await;

        match cmd {
            Command::Enter { master, resp } => {
                let prompt = terminal_list.enter_terminal(master).map(|terminal| {
                    terminal
                        .prompt
                        .as_ref()
                        .map_or_else(Vec::new, |p| p.clone())
                });

                let _ = resp.send(prompt);
            }
            Command::Leave { resp } => {
                terminal_list.leave_terminal()?;
                let _ = resp.send(true);
            }
            Command::List { resp } => {
                let terms = terminal_list.terminals.keys().copied().collect::<Vec<_>>();
                let _ = resp.send(terms);
            }
        }
    }

    Err(anyhow!("Unexpected error."))
}

pub async fn monitor_terminal(fd: RawFd) -> Result<()> {
    let ref_terminal_list = TERMINAL_LIST.clone();

    let mut terminal_list = ref_terminal_list.lock().await;
    terminal_list.add_terminal(fd);
    drop(terminal_list);

    let mut reader = unsafe { File::from_raw_fd(fd) };
    loop {
        let buf = match async_read(&mut reader).await {
            Ok(b) => b,
            Err(e) => {
                ref_terminal_list.lock().await.remove_terminal(fd)?;
                return Err(e);
            }
        };

        let mut terminal_list = ref_terminal_list.lock().await;
        let terminal = terminal_list.terminals.get_mut(&fd).unwrap();

        if terminal.active {
            if let Err(e) = io::copy(&mut &buf[..], &mut io::stdout()).await {
                terminal_list.remove_terminal(fd)?;
                return Err(e.into());
            }
        }

        if buf.ends_with(b"# ") || buf.ends_with(b"$ ") {
            match buf.iter().rposition(|&b| b == b'\n') {
                Some(p) => terminal.set_prompt(buf[p + 1..].to_vec()),
                None => terminal.set_prompt(buf),
            }
        }
    }
}

pub fn run_acond_terminal(tx: mpsc::Sender<Command>) -> Result<()> {
    let mut editor = Editor::<()>::new()?;

    loop {
        let line = match editor.readline("[Acond]: ") {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => continue,
            Err(e) => return Err(e.into()),
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match line {
            "?" | "h" | "help" => println!(
                "list[l]         -- List all the container pseudo terminals.\n\
                 enter[e] master -- Enter the specified container pseudo terminal. Press Ctrl+Alt+O and then x|X to back to acond command line.\n\
                 debug[d]        -- Enter VM pseudo terminal for debug purpose if sh or bash exists.\n\
                 help[h|?]       -- Show help messages.\n"
            ),
            "l" | "list" => list_terminals(tx.clone())?,
            "d" | "debug" => {
                if let Some(fd) = start_pod_terminal()? {
                    enter_pod_terminal(fd)?;
                } else {
                    eprintln!("No shell is found to launch debug terminal.");
                }
            }
            _ => {
                if let Some(fd) = validate_command(line) {
                    enter_container_terminal(fd, tx.clone())?;
                } else {
                    eprintln!("Please input correct command, '?|h|help' for help.");
                }
            }
        }

        editor.add_history_entry(line);
    }
}

fn list_terminals(tx: mpsc::Sender<Command>) -> Result<()> {
    let (resp_tx, resp_rx) = oneshot::channel();
    let _ = tx.blocking_send(Command::List { resp: resp_tx });

    println!("\x1b[1;32mmaster\tslave\x1b[0m");
    if let Ok(fds) = resp_rx.blocking_recv() {
        for fd in fds {
            println!("{}\t{}", fd, get_ptsname(fd)?);
        }
    }

    Ok(())
}

fn start_pod_terminal() -> Result<Option<RawFd>> {
    let shells = vec!["/bin/bash", "/bin/sh"];

    if let Some(shell) = shells.into_iter().find(|p| PathBuf::from(p).exists()) {
        let res = unsafe { pty::forkpty(None, None)? };

        match res.fork_result {
            ForkResult::Parent { child: _ } => {
                return Ok(Some(res.master));
            }
            ForkResult::Child => {
                let filename = CString::new(shell).unwrap();
                let _ = unistd::execvp(filename.as_c_str(), &[filename.as_ref()]).map_err(|err| {
                    process::exit(err as i32);
                });
            }
        }
    }

    Ok(None)
}

fn enter_pod_terminal(fd: RawFd) -> Result<()> {
    let setting = TerminalSetting::new();
    setting.enter_terminal()?;

    let mut fdset = FdSet::new();
    fdset.insert(fd);
    fdset.insert(libc::STDIN_FILENO);

    loop {
        let mut rfdset = fdset;
        select::select(None, Some(&mut rfdset), None, None, None)?;

        if rfdset.contains(fd) {
            if let Ok(buf) = read(fd) {
                unistd::write(libc::STDOUT_FILENO, &buf)?;
            } else {
                unistd::close(fd)?;
                setting.leave_terminal()?;

                return Ok(());
            }
        }

        if rfdset.contains(libc::STDIN_FILENO) {
            let buf = read(libc::STDIN_FILENO)?;
            if let Err(e) = unistd::write(fd, &buf) {
                unistd::close(fd)?;
                setting.leave_terminal()?;

                return Err(e.into());
            }
        }
    }
}

fn validate_command(cmd: &str) -> Option<i32> {
    let params = cmd.split_whitespace().collect::<Vec<_>>();

    if (cmd.starts_with("e ") || cmd.starts_with("enter ")) && params.len() == 2 {
        params[1].parse().ok()
    } else {
        None
    }
}

fn enter_container_terminal(fd: RawFd, tx: mpsc::Sender<Command>) -> Result<()> {
    let (resp_tx, resp_rx) = oneshot::channel();
    let _ = tx.blocking_send(Command::Enter {
        master: fd,
        resp: resp_tx,
    });

    match resp_rx.blocking_recv() {
        Ok(Some(res)) => {
            stdio::stdout().write_all(res.as_slice())?;
            stdio::stdout().flush()?;
        }
        Ok(None) => {
            eprintln!("Master {fd} is not found.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }

    let mut hotkey_pressed = false;

    let mut fdset = FdSet::new();
    fdset.insert(libc::STDIN_FILENO);
    let mut efdset = FdSet::new();
    efdset.insert(fd);

    loop {
        let mut rfdset = fdset;
        let mut eefdset = efdset;
        select::select(None, Some(&mut rfdset), None, Some(&mut eefdset), None)?;

        if rfdset.contains(libc::STDIN_FILENO) {
            let mut buf = read(libc::STDIN_FILENO)?;

            if hotkey_pressed {
                if buf[0] == 0x58 || buf[0] == 0x78 {
                    let (resp_tx, resp_rx) = oneshot::channel();
                    let _ = tx.blocking_send(Command::Leave { resp: resp_tx });
                    let _ = resp_rx.blocking_recv();
                    println!();

                    return Ok(());
                }

                hotkey_pressed = false;
            }

            if is_hotkey_pressed(&mut buf) {
                hotkey_pressed = true;
            }

            unistd::write(fd, &buf)?;
        }

        if eefdset.contains(fd) {
            return Ok(());
        }
    }
}

fn get_ptsname(fd: RawFd) -> Result<String> {
    let mut name_buf = Vec::<libc::c_char>::with_capacity(64);
    let name_buf_ptr = name_buf.as_mut_ptr();
    let cname = unsafe {
        let cap = name_buf.capacity();
        if libc::ptsname_r(fd, name_buf_ptr, cap) != 0 {
            return Err(nix::Error::last().into());
        }
        CStr::from_ptr(name_buf.as_ptr())
    };

    Ok(cname.to_string_lossy().into_owned())
}

fn is_hotkey_pressed(buf: &mut Vec<u8>) -> bool {
    let hk: [u8; 2] = [0x1b, 0x0f];

    match buf.windows(hk.len()).position(|w| w == hk) {
        Some(i) => {
            buf.drain(i..i + hk.len());
            true
        }
        None => false,
    }
}

fn read(fd: RawFd) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; utils::BUFF_SIZE];

    loop {
        match unistd::read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if n < chunk.len() {
                    break;
                }
            }
            Err(Errno::EAGAIN) => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(buf)
}

async fn async_read<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; utils::BUFF_SIZE];

    loop {
        match reader.read(&mut chunk).await {
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

// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::{image::Image, report};
use anyhow::{anyhow, Result};
use data_encoding::HEXLOWER;
use nix::{
    fcntl::{self, FlockArg},
    mount,
    unistd::Pid,
};
use openssl::{
    hash::{DigestBytes, Hasher, MessageDigest},
    rand,
    sign::Verifier,
    x509::X509,
};
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, File},
    io::{self, BufRead, BufReader, Cursor, ErrorKind, Write},
    os::unix::fs as unixfs,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    str,
    sync::atomic::{AtomicU32, Ordering},
};
use tar::Archive;

pub const REPORT_API_VERSION: &str = "1.0.0";
pub const ERR_CFG_INVALID_VSOCK_PORT: &str = "Invalid kernel cmdline parameter - acond.vsock_port";
pub const ERR_CFG_INVALID_TCPIP_PORT: &str = "Invalid kernel cmdline parameter - acond.tcp_port";
pub const ERR_CFG_INVALID_TIMEOUT: &str = "Invalid kernel cmdline parameter - acond.timeout";
pub const ERR_RPC_INCOMPATIBLE_POLICY: &str = "Incompatible polices";
pub const ERR_RPC_MANIFEST_FINALIZED: &str = "Manifests finalized";
pub const ERR_RPC_INVALID_SIGNATURE: &str = "Invalid digital signature";
pub const ERR_RPC_INVALID_CERTIFICATE: &str = "Invalid certificate";
pub const ERR_RPC_INVALID_HASH_ALGORITHM: &str = "Invalid hash algorithm";
pub const ERR_RPC_REJECT_BLOB: &str = "No referencing manifest";
pub const ERR_RPC_INVALID_IMAGE_ID: &str = "Invalid Image ID";
pub const ERR_RPC_INVALID_CONTAINER_ID: &str = "Invalid Container ID";
pub const ERR_RPC_CONTAINER_TERMINATED: &str = "Container terminated";
pub const ERR_RPC_CONTAINER_RESTART_TIMEOUT: &str = "Timeout restarting container";
pub const ERR_RPC_CONTAINER_NOT_ALLOW_RESTART: &str = "Restarting container not allowed";
pub const ERR_RPC_CONTAINER_NOT_ALLOW_KILL: &str = "Signal not allowed";
pub const ERR_RPC_INVALID_LPOLICY_FORMAT: &str = "Invalid launch policy format";
pub const ERR_RPC_INVALID_MALIAS_FORMAT: &str = "Invalid manifest alias format";
pub const ERR_RPC_INVALID_ENTRYPOINT: &str = "Invalid entrypoint";
pub const ERR_RPC_INVALID_REQUEST_TYPE: &str = "Invalid request type";
#[cfg(not(feature = "interactive"))]
pub const ERR_RPC_INVALID_TIMEOUT: &str = "Invalid timeout";
pub const ERR_RPC_BUFFER_EXCEED: &str = "Stdin buffer size exceeds capture size";
pub const ERR_RPC_PRIVATE_ENTRYPOINT: &str = "Private entrypoint";
pub const ERR_RPC_SYSTEM_ERROR: &str = "System error, errno: {}";
pub const ERR_IPC_INVALID_REQUEST: &str = "Invalid structure format";
pub const ERR_IPC_NOT_SUPPORTED: &str = "Request not supported";
pub const ERR_ATTEST_NOT_SUPPORTED: &str = "Attestation not supported";
pub const ERR_UNEXPECTED: &str = "Unexpected error";

const STORAGE_ROOT: &str = "/run/acond";
const MEASURE_ROOT: &str = "/run/rtmr";
const CONTENTS_DIR: &str = "contents";
const IMAGES_DIR: &str = "images";
const IMAGE_LAYER: &str = "l";
const CONTAINERS_DIR: &str = "containers";
const SIGNER_DIR: &str = "signer";
const IMAGE_DIR: &str = "image";
const TOP_DIR: &str = "top";
const ROOTFS_DIR: &str = "rootfs";
const UPPER_DIR: &str = "upper";
const WORK_DIR: &str = "work";
const ACON_MANIFEST: &str = "acon-manifest.json";
const RTMR3_LOG: &str = "rtmr3.log";
pub const SHA256: &str = "sha256";
pub const SHA384: &str = "sha384";
pub const SHA512: &str = "sha512";

pub const BUFF_SIZE: usize = 0x400;
pub const MAX_BUFF_SIZE: usize = 0x100000;

pub const CLIENT_UID: u32 = 1;
pub const BLOB_DIR: &str = "/run/user/1";

// Reserve 1 for the deprivileged process
static CONTAINER_SERIES: AtomicU32 = AtomicU32::new(CLIENT_UID + 1);

lazy_static! {
    static ref TOP_SUB_DIR: HashSet<&'static str> = {
        let mut m = HashSet::new();
        m.insert("dev");
        m.insert("dev/pts");
        m.insert("proc");
        m.insert("tmp");
        m.insert("run");
        m.insert("shared");
        m
    };
}

#[derive(Copy, Clone)]
enum DAlgorithm {
    SHA256 = 0x01,
    SHA384 = 0x02,
    SHA512 = 0x04,
}

fn alg2u32(alg: &DAlgorithm) -> u32 {
    *alg as u32
}

pub fn verify_signature(buffer: &[u8], signature: &[u8], certificate: &[u8]) -> Result<bool> {
    let x509 = X509::from_der(certificate)?;
    let pubkey = x509.public_key()?;
    let algorithm = x509
        .signature_algorithm()
        .object()
        .to_string()
        .to_lowercase();
    let digest = if algorithm.contains(SHA256) {
        Ok(MessageDigest::sha256())
    } else if algorithm.contains(SHA384) {
        Ok(MessageDigest::sha384())
    } else if algorithm.contains(SHA512) {
        Ok(MessageDigest::sha512())
    } else {
        Err(anyhow!(ERR_RPC_INVALID_CERTIFICATE))
    }?;

    let mut verifier = Verifier::new(digest, pubkey.as_ref())?;

    Ok(verifier.verify_oneshot(signature, buffer)?)
}

pub fn calc_certificate_digest(certificate: &[u8]) -> Result<(String, String)> {
    let x509 = X509::from_der(certificate)?;
    let algorithm = x509
        .signature_algorithm()
        .object()
        .to_string()
        .to_lowercase();
    if algorithm.contains(SHA256) {
        Ok((SHA256.to_string(), calc_sha256_from_buffer(certificate)?))
    } else if algorithm.contains(SHA384) {
        Ok((SHA384.to_string(), calc_sha384_from_buffer(certificate)?))
    } else if algorithm.contains(SHA512) {
        Ok((SHA512.to_string(), calc_sha512_from_buffer(certificate)?))
    } else {
        Err(anyhow!(ERR_RPC_INVALID_CERTIFICATE))
    }
}

pub fn calc_image_digest(
    algorithm: &String,
    signer_digest: &String,
    manifest: &[u8],
) -> Result<(String, String)> {
    if algorithm == SHA256 {
        let manifest_digest = calc_sha256_from_buffer(manifest)?;
        Ok((
            format!("{}/{}/{}", algorithm, signer_digest, manifest_digest),
            manifest_digest,
        ))
    } else if algorithm == SHA384 {
        let manifest_digest = calc_sha384_from_buffer(manifest)?;
        Ok((
            format!("{}/{}/{}", algorithm, signer_digest, manifest_digest),
            manifest_digest,
        ))
    } else if algorithm == SHA512 {
        let manifest_digest = calc_sha512_from_buffer(manifest)?;
        Ok((
            format!("{}/{}/{}", algorithm, signer_digest, manifest_digest),
            manifest_digest,
        ))
    } else {
        Err(anyhow!(ERR_RPC_INVALID_HASH_ALGORITHM))
    }
}

pub fn calc_blob_digest(algorithm: u32, data: &[u8]) -> Result<Vec<String>> {
    let mut layers = Vec::new();

    if algorithm & alg2u32(&DAlgorithm::SHA256) != 0 {
        layers.push(format!("{}/{}", SHA256, calc_sha256_from_buffer(data)?));
    }

    if algorithm & alg2u32(&DAlgorithm::SHA384) != 0 {
        layers.push(format!("{}/{}", SHA384, calc_sha384_from_buffer(data)?));
    }

    if algorithm & alg2u32(&DAlgorithm::SHA512) != 0 {
        layers.push(format!("{}/{}", SHA512, calc_sha512_from_buffer(data)?));
    }

    Ok(layers)
}

fn calc_sha256_from_buffer(buffer: &[u8]) -> Result<String> {
    let digest = calc_digest_from_buffer(buffer, MessageDigest::sha256())?;
    Ok(HEXLOWER.encode(digest.as_ref()))
}

fn calc_sha384_from_buffer(buffer: &[u8]) -> Result<String> {
    let digest = calc_digest_from_buffer(buffer, MessageDigest::sha384())?;
    Ok(HEXLOWER.encode(digest.as_ref()))
}

fn calc_sha512_from_buffer(buffer: &[u8]) -> Result<String> {
    let digest = calc_digest_from_buffer(buffer, MessageDigest::sha512())?;
    Ok(HEXLOWER.encode(digest.as_ref()))
}

fn calc_digest_from_buffer(buffer: &[u8], algorithm: MessageDigest) -> Result<DigestBytes> {
    let mut hasher = Hasher::new(algorithm)?;
    hasher.update(buffer)?;
    Ok(hasher.finish()?)
}

pub fn measure_image(image_id: Option<&str>) -> Result<()> {
    let write_exclusive = |file: &PathBuf, contents: &str| -> Result<()> {
        let mut f = File::options()
            .create_new(true)
            .append(true)
            .open(file)
            .or_else(|e| -> io::Result<File> {
                if e.kind() == ErrorKind::AlreadyExists {
                    File::options().append(true).open(file)
                } else {
                    Err(e)
                }
            })?;

        let fd = f.as_raw_fd();
        fcntl::flock(fd, FlockArg::LockExclusive)?;
        writeln!(f, "{}", contents)?;

        Ok(())
    };

    let rtmr3_path = PathBuf::from(MEASURE_ROOT).join(RTMR3_LOG);
    if !rtmr3_path.exists() {
        let measurement_path = PathBuf::from(MEASURE_ROOT);
        fs::create_dir_all(measurement_path)?;
        File::create(&rtmr3_path)?;

        // hardcode temporarily
        let contents = "INIT sha384/000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        report::extend_rtmr(contents)?;
        write_exclusive(&rtmr3_path, contents)?;
    }

    if let Some(id) = image_id {
        let contents = format!("github.com/intel/ACON AddManifest {}", id);
        report::extend_rtmr(contents.as_str())?;
        write_exclusive(&rtmr3_path, contents.as_str())?;
    } else {
        let contents = "github.com/intel/ACON Finalize";
        report::extend_rtmr(contents)?;
        write_exclusive(&rtmr3_path, contents)?;
    }

    Ok(())
}

pub fn get_measurement_rtmr3() -> Result<Vec<String>> {
    let mut log = vec![];

    let file = File::open(format!("{}/{}", MEASURE_ROOT, RTMR3_LOG))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        log.push(line?);
    }

    Ok(log)
}

pub fn setup_image_dtree(image: &Image, manifest: &[u8]) -> Result<()> {
    let mut image_path = PathBuf::from(STORAGE_ROOT);
    image_path.push(IMAGES_DIR);
    image_path.push(&image.id);
    fs::create_dir_all(&image_path)?;

    let mut acon_manifest = PathBuf::from(&image_path);
    acon_manifest.push(ACON_MANIFEST);
    fs::write(acon_manifest, manifest)?;

    image_path.push(IMAGE_LAYER);
    fs::create_dir_all(&image_path)?;

    for (index, layer) in image.manifest.layers.iter().enumerate() {
        let original = format!("../../../../../{}/{}", CONTENTS_DIR, layer);
        let link = format!("{}", index);
        create_relative_link(&image_path, &original, &link)?;
    }

    Ok(())
}

pub fn setup_container_dtree(image: &Image, container_id: u32) -> Result<String> {
    let mut container_path = PathBuf::from(STORAGE_ROOT);
    container_path.push(CONTAINERS_DIR);
    container_path.push(format!("{}", container_id));
    fs::create_dir_all(&container_path)?;

    let original = format!("../../{}/{}", IMAGES_DIR, image.id);
    create_relative_link(&container_path, &original, &String::from(IMAGE_DIR))?;

    let top_path = setup_top_dtree(&container_path)?;

    let root_path = Path::new(&container_path).join(ROOTFS_DIR);
    fs::create_dir_all(root_path)?;

    let mut image_dirs: Vec<PathBuf> = vec![];
    let image_path = Path::new(&container_path).join(IMAGE_DIR).join(IMAGE_LAYER);

    for entry in fs::read_dir(image_path)? {
        let path = entry?.path();
        if path.is_dir() {
            image_dirs.push(path);
        }
    }

    image_dirs.sort_by_key(|dir| {
        dir.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u32>()
            .unwrap()
    });
    image_dirs.reverse();

    let mut overlay_fs = "lowerdir=".to_string();
    overlay_fs.push_str(top_path.to_str().unwrap());
    for dir in &image_dirs {
        overlay_fs.push(':');
        overlay_fs.push_str(dir.to_str().unwrap());
    }

    if image.manifest.writable_fs {
        let upper_path = Path::new(&container_path).join(UPPER_DIR);
        fs::create_dir_all(&upper_path)?;
        let work_path = Path::new(&container_path).join(WORK_DIR);
        fs::create_dir_all(&work_path)?;

        overlay_fs.push_str(format!(",upperdir={}", upper_path.to_str().unwrap()).as_str());
        overlay_fs.push_str(format!(",workdir={}", work_path.to_str().unwrap()).as_str());
    }

    Ok(overlay_fs)
}

fn setup_top_dtree(root_path: &Path) -> Result<PathBuf> {
    let mut top_path = root_path.to_path_buf();
    top_path.pop();
    top_path.push(TOP_DIR);

    for dir in TOP_SUB_DIR.iter() {
        let path = PathBuf::from(&top_path).join(dir);
        if path.exists() {
            continue;
        }
        fs::create_dir_all(&path)?;
    }

    Ok(top_path)
}

pub fn destroy_container_dtree(container_id: u32) -> Result<()> {
    let mut container_path = PathBuf::from(STORAGE_ROOT);
    container_path.push(CONTAINERS_DIR);
    container_path.push(format!("{}", container_id));
    fs::remove_dir_all(&container_path)?;

    Ok(())
}

pub fn umount_container_rootfs(container_id: u32) -> Result<()> {
    let root_path = Path::new(STORAGE_ROOT)
        .join(CONTAINERS_DIR)
        .join(format!("{}", container_id))
        .join(ROOTFS_DIR);

    if root_path.exists() {
        mount::umount(&root_path)?;
    }

    Ok(())
}

pub fn get_rootfs_path(container_id: u32) -> PathBuf {
    Path::new(STORAGE_ROOT)
        .join(CONTAINERS_DIR)
        .join(format!("{}", container_id))
        .join(ROOTFS_DIR)
}

pub fn create_alias_link(image: &Image) -> Result<()> {
    if !image.manifest.aliases.contents.is_empty() {
        let content_path = Path::new(STORAGE_ROOT)
            .join(CONTENTS_DIR)
            .join(SIGNER_DIR)
            .join(&image.hash_algorithm)
            .join(&image.signer_digest);
        fs::create_dir_all(&content_path)?;

        for (key, value) in &image.manifest.aliases.contents {
            for alias in value {
                if key.starts_with(SIGNER_DIR) {
                    let original = format!("../..{}", key.strip_prefix(SIGNER_DIR).unwrap());
                    create_relative_link(&content_path, &original, alias)?;
                } else {
                    let original = format!("../../../{}", key);
                    create_relative_link(&content_path, &original, alias)?;
                }
            }
        }
    }

    if !image.manifest.aliases.itself.is_empty() {
        let self_path = Path::new(STORAGE_ROOT)
            .join(IMAGES_DIR)
            .join(&image.hash_algorithm)
            .join(&image.signer_digest);
        fs::create_dir_all(&self_path)?;

        for value in image.manifest.aliases.itself.values() {
            for alias in value {
                create_relative_link(&self_path, &image.manifest_digest, alias)?;
            }
        }
    }

    Ok(())
}

fn create_relative_link(current: &PathBuf, original: &String, link: &String) -> Result<()> {
    let backup = env::current_dir()?;
    env::set_current_dir(current)?;
    let plink = Path::new(link);
    if !plink.exists() {
        unixfs::symlink(original, plink)?;
    }
    env::set_current_dir(backup)?;

    Ok(())
}

pub fn save_blob(layers: &Vec<String>, data: &[u8]) -> Result<()> {
    let main_layer = || -> Result<String> {
        for layer in layers {
            if layer.starts_with(SHA384) {
                return Ok(layer.clone());
            }
        }

        Ok(format!("{}/{}", SHA384, calc_sha384_from_buffer(data)?))
    };

    let content_path = Path::new(STORAGE_ROOT)
        .join(CONTENTS_DIR)
        .join(main_layer()?);
    fs::create_dir_all(&content_path)?;

    let mut archive = Archive::new(Cursor::new(data));
    archive.unpack(&content_path)?;

    let original = format!("../{}", main_layer()?);
    for layer in layers {
        if layer.starts_with(SHA384) {
            continue;
        }

        let dirs = layer.split('/').collect::<Vec<_>>();
        let link = String::from(dirs[1]);

        let current_path = Path::new(STORAGE_ROOT).join(CONTENTS_DIR).join(dirs[0]);
        if !current_path.exists() {
            fs::create_dir_all(&current_path)?;
        }

        create_relative_link(&current_path, &original, &link)?;
    }

    Ok(())
}

pub fn get_missing_layers(image_id: &String, layers: &[String]) -> Result<Vec<String>> {
    let image_path = Path::new(STORAGE_ROOT)
        .join(IMAGES_DIR)
        .join(image_id)
        .join(IMAGE_LAYER);

    if !image_path.exists() {
        return Ok(layers.to_owned());
    }

    let mut missing_layers = Vec::new();
    for entry in image_path.read_dir()? {
        if let Ok(res) = entry?.path().read_link() {
            if !res.exists() {
                let l = res.to_str().unwrap().split('/').collect::<Vec<_>>();
                if l.len() >= 2 {
                    missing_layers.push(format!("{}{}{}", l[l.len() - 2], "/", l[l.len() - 1]));
                }
            }
        }
    }

    Ok(missing_layers)
}

pub fn get_manifest(image_id: &String) -> Result<String> {
    let manifest_path = Path::new(STORAGE_ROOT)
        .join(IMAGES_DIR)
        .join(image_id)
        .join(ACON_MANIFEST);

    let content = fs::read_to_string(manifest_path)?;
    Ok(content)
}

pub fn get_container_info(container_id: u32, container_pid: Pid) -> Result<(u32, String)> {
    let prefix = PathBuf::from(STORAGE_ROOT)
        .join(CONTAINERS_DIR)
        .join(format!("{}", container_id))
        .join(ROOTFS_DIR);
    let link = fs::read_link(format!("/proc/{}/exe", container_pid))?;
    let exe = link.strip_prefix(prefix)?;

    let fstatus = format!("/proc/{}/status", container_pid);
    let reader = BufReader::new(File::open(&fstatus)?);

    let mut name = String::new();
    let mut state = 0;

    for l in reader.lines() {
        let line = l?;

        let mut parts = line.split_ascii_whitespace();
        match parts.next() {
            Some("Name:") => {
                name = parts
                    .next()
                    .ok_or_else(|| anyhow!("File format error of {}.", fstatus))?
                    .into();
            }
            Some("State:") => {
                state = parts
                    .next()
                    .ok_or_else(|| anyhow!("File format error of {}.", fstatus))?
                    .chars()
                    .next()
                    .ok_or_else(|| anyhow!("File format error of {}.", fstatus))?
                    as u32;
            }
            _ => continue,
        }
    }

    Ok((state, format!("{}[/{}]", name, exe.to_str().unwrap())))
}

pub fn get_nounces(requestor_nonce_hi: u64, requestor_nonce_lo: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    let requestor_nonce =
        (((requestor_nonce_hi as u128) << 64) | (requestor_nonce_lo as u128)).to_ne_bytes();

    let mut acond_nonce = [0; 16];
    rand::rand_bytes(&mut acond_nonce)?;

    Ok((requestor_nonce.to_vec(), acond_nonce.to_vec()))
}

pub fn is_init_process(pid: i32) -> Result<bool> {
    let file = File::open(format!("/proc/{}/status", pid))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => return Ok(false),
        };

        if line.starts_with("NSpid:") {
            let nspid = line.split_ascii_whitespace().collect::<Vec<_>>();
            return Ok(nspid.get(2) == Some(&"1"));
        }
    }

    Ok(false)
}

pub fn is_rootfs_mounted() -> bool {
    Path::new("/proc/mounts").exists()
}

pub fn is_mounted(path: &str) -> bool {
    let file = match File::open("/proc/mounts") {
        Ok(f) => f,
        _ => return false,
    };
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => return false,
        };
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() > 1 && fields[1] == path {
            return true;
        }
    }

    false
}

pub fn start_with_uppercase(command: &str) -> bool {
    command
        .chars()
        .next()
        .map(|c| c.is_uppercase())
        .unwrap_or(false)
}

pub fn get_env_vars(manifest_envs: &Vec<String>, param_envs: &Vec<String>) -> Result<Vec<String>> {
    let mut env_vars: HashMap<&str, &str> = HashMap::new();
    let mut m: HashMap<&str, Vec<&str>> = HashMap::new();

    for e in manifest_envs {
        if let Some((key, value)) = e.split_once('=') {
            if m.contains_key(key) {
                if m.get(key).unwrap().is_empty() || m.get(key).unwrap().contains(&value) {
                    return Err(anyhow!("Format error of environment array in manifest."));
                } else {
                    m.get_mut(key).unwrap().push(value);
                }
            } else {
                m.insert(key, vec![value]);
            }
        } else if m.contains_key(e.as_str()) {
            return Err(anyhow!("Format error of environment array in manifest."));
        } else {
            m.insert(e, vec![]);
        }
    }

    // "HTTPS_RPXOY=https://child-prc.intel.com:913", "HTTPS_RPXOY=https://child-prc.intel.com:914"
    for e in param_envs {
        if let Some((key, value)) = e.split_once('=') {
            if env_vars.contains_key(key) {
                return Err(anyhow!("Format error of environment array in commandline."));
            }

            if m.contains_key(key)
                && (m.get(key).unwrap().is_empty() || m.get(key).unwrap().contains(&value))
            {
                env_vars.insert(key, value);
            } else {
                return Err(anyhow!("{} is not in environment array.", e));
            }
        } else {
            return Err(anyhow!("Format error of environment array in commandline."));
        }
    }

    for (key, value) in m {
        if !env_vars.contains_key(key) && !value.is_empty() {
            env_vars.insert(key, value[0]);
        }
    }

    Ok(env_vars
        .into_iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect::<Vec<_>>())
}

pub fn generate_cid() -> Result<u32> {
    let mut contents = fs::read_to_string("/proc/sys/kernel/overflowuid")?;
    if contents.ends_with('\n') {
        contents.truncate(contents.len() - 1);
    }

    let overflow_uid = contents.parse::<u32>()?;
    let cid = CONTAINER_SERIES.fetch_add(1, Ordering::Relaxed);
    if cid != overflow_uid {
        return Ok(cid);
    }

    Ok(CONTAINER_SERIES.fetch_add(1, Ordering::Relaxed))
}

#[cfg(test)]
mod unit_test {
    use super::*;

    // $ echo -n "acond" | sha256sum
    // ebc7a2f333142d0a69f6e85df32d5bc2c3ed3e0bb637b8f914643616e0c2ca18
    // $ echo -n "acond" | sha384sum
    // 29c19882a38552dbd97e59918de0f41186f8cbd05e90b6fc49dcca1a7e96efcfecd66cc224fea72c634eb3a490853c27
    // $ echo -n "acond" | sha512sum
    // 160d7d1ad88694658ed0bef536803ecea15b34d72fb0fd8bb70830c9b3f9552e260787b488fcc3d43000647301eafe8a695821634f8fe30209cd4f67ed6810ff
    const ACOND: &[u8] = "acond".as_bytes();
    const ACOND_SHA256: &str = "ebc7a2f333142d0a69f6e85df32d5bc2c3ed3e0bb637b8f914643616e0c2ca18";
    const ACOND_SHA384: &str = "29c19882a38552dbd97e59918de0f41186f8cbd05e90b6fc49dcca1a7e96efcfecd66cc224fea72c634eb3a490853c27";
    const ACOND_SHA512: &str = "160d7d1ad88694658ed0bef536803ecea15b34d72fb0fd8bb70830c9b3f9552e260787b488fcc3d43000647301eafe8a695821634f8fe30209cd4f67ed6810ff";

    #[test]
    fn test_calc_image_digest() {
        assert_eq!(
            calc_image_digest(&SHA256.to_string(), &ACOND_SHA256.to_string(), ACOND).unwrap(),
            (
                format!("{}/{}/{}", SHA256, ACOND_SHA256, ACOND_SHA256),
                ACOND_SHA256.to_string()
            )
        );

        assert_eq!(
            calc_image_digest(&SHA384.to_string(), &ACOND_SHA384.to_string(), ACOND).unwrap(),
            (
                format!("{}/{}/{}", SHA384, ACOND_SHA384, ACOND_SHA384),
                ACOND_SHA384.to_string()
            )
        );

        assert_eq!(
            calc_image_digest(&SHA512.to_string(), &ACOND_SHA512.to_string(), ACOND).unwrap(),
            (
                format!("{}/{}/{}", SHA512, ACOND_SHA512, ACOND_SHA512),
                ACOND_SHA512.to_string()
            )
        );

        assert!(calc_image_digest(&"".to_string(), &"".to_string(), ACOND).is_err());
    }

    #[test]
    fn test_calc_blob_digest() {
        {
            let layers = calc_blob_digest(0, ACOND).unwrap();
            assert!(layers.is_empty());
        }

        {
            let alg = alg2u32(&DAlgorithm::SHA256)
                | alg2u32(&DAlgorithm::SHA384)
                | alg2u32(&DAlgorithm::SHA512);
            let layers = calc_blob_digest(alg, ACOND).unwrap();

            assert_eq!(layers.len(), 3);
            assert_eq!(layers[0], format!("{}/{}", SHA256, ACOND_SHA256));
            assert_eq!(layers[1], format!("{}/{}", SHA384, ACOND_SHA384));
            assert_eq!(layers[2], format!("{}/{}", SHA512, ACOND_SHA512));
        }
    }

    #[test]
    fn test_calc_sha256_from_buffer() {
        assert_eq!(calc_sha256_from_buffer(ACOND).unwrap(), ACOND_SHA256);
    }

    #[test]
    fn test_calc_sha384_from_buffer() {
        assert_eq!(calc_sha384_from_buffer(ACOND).unwrap(), ACOND_SHA384);
    }

    #[test]
    fn test_calc_sha512_from_buffer() {
        assert_eq!(calc_sha512_from_buffer(ACOND).unwrap(), ACOND_SHA512);
    }

    #[test]
    fn test_calc_digest_from_buffer() {
        assert_eq!(
            HEXLOWER.encode(
                calc_digest_from_buffer(ACOND, MessageDigest::sha256())
                    .unwrap()
                    .as_ref()
            ),
            ACOND_SHA256
        );
    }
}

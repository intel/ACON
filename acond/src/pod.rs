// Copyright (C) 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    container::Container,
    image::{AttestData, AttestDataValue, Image},
    utils,
};
use anyhow::{anyhow, Result};
use std::collections::{BTreeMap, HashMap};
use tokio::sync::mpsc::Sender;

#[derive(Debug)]
pub struct Pod {
    pub images: HashMap<String, Image>,
    pub containers: HashMap<u32, Container>,
    pub finalized: bool,
    pub timeout_tx: Option<Sender<bool>>,
}

impl Pod {
    pub fn new(tx: Option<Sender<bool>>) -> Self {
        Pod {
            images: HashMap::new(),
            containers: HashMap::new(),
            finalized: false,
            timeout_tx: tx,
        }
    }

    pub fn add_image(&mut self, image: Image) {
        self.images.insert(image.id.clone(), image);
    }

    pub fn get_image(&self, image_id: &str) -> Option<&Image> {
        self.images.get(image_id)
    }

    pub fn get_container(&self, container_id: &u32) -> Option<&Container> {
        self.containers.get(container_id)
    }

    pub fn get_container_mut(&mut self, container_id: &u32) -> Option<&mut Container> {
        self.containers.get_mut(container_id)
    }

    pub fn add_container(&mut self, container: Container) {
        self.containers.insert(container.id, container);
    }

    pub fn has_alive_container(&self) -> bool {
        for (_, c) in self.containers.iter() {
            if c.is_running() {
                return true;
            }
        }

        false
    }

    pub fn is_manifest_accepted(&mut self, image: &Image) -> Result<bool> {
        if self.has_rejecting_image() {
            if self.accept_incoming_image(image)? {
                if image.manifest.policy.reject_unaccepted {
                    self.accept_existed_rejecting_images(image)
                } else {
                    Ok(true)
                }
            } else {
                Ok(false)
            }
        } else if image.manifest.policy.reject_unaccepted {
            self.accept_all_existed_images(image)
        } else {
            Ok(true)
        }
    }

    pub fn is_blob_accepted(&self, digests: &[String]) -> bool {
        if self.images.is_empty() {
            return false;
        }

        for (_, i) in self.images.iter() {
            for l in &i.manifest.layers {
                if digests.contains(l) {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_attestation_data(
        &self,
        requestor_nonce: Vec<u8>,
        acond_nonce: Vec<u8>,
        attest_data: Option<(u32, AttestDataValue)>,
    ) -> Result<String> {
        let mut attest_data_map = BTreeMap::new();

        for image_id in self.images.keys() {
            attest_data_map.insert(image_id.clone(), BTreeMap::new());
        }

        if let Some((cid, data)) = attest_data {
            for container in self.containers.values() {
                let ref_data = attest_data_map.get_mut(&container.image_id).unwrap();
                if container.id == cid {
                    ref_data.insert(container.id, data.clone());
                } else {
                    ref_data.insert(container.id, container.attest_data.clone());
                }
            }
        } else {
            for container in self.containers.values() {
                let ref_data = attest_data_map.get_mut(&container.image_id).unwrap();
                ref_data.insert(container.id, container.attest_data.clone());
            }
        }

        let attest_data = AttestData {
            api_version: utils::REPORT_API_VERSION.to_owned(),
            requestor_nonce,
            acond_nonce,
            attestation_data: attest_data_map,
        };

        serde_json::to_string(&attest_data).map_err(|e| anyhow!(e))
    }

    fn has_rejecting_image(&self) -> bool {
        for (_, image) in self.images.iter() {
            if image.manifest.policy.reject_unaccepted {
                return true;
            }
        }

        false
    }

    fn accept_all_existed_images(&self, image: &Image) -> Result<bool> {
        for (_, i) in self.images.iter() {
            if !accept_image(&image.manifest.policy.accepts, i)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn accept_incoming_image(&self, image: &Image) -> Result<bool> {
        for (_, i) in self.images.iter() {
            if accept_image(&i.manifest.policy.accepts, image)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn accept_existed_rejecting_images(&self, image: &Image) -> Result<bool> {
        for (_, i) in self.images.iter() {
            if !i.manifest.policy.reject_unaccepted {
                continue;
            }

            if accept_image(&image.manifest.policy.accepts, i)? {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

fn accept_image(accepts: &Vec<String>, image: &Image) -> Result<bool> {
    let signer_digest = &image.signer_digest;
    let manifest_digest = &image.manifest_digest;
    let itself_aliases = &image.manifest.aliases.itself;

    for accept in accepts {
        let fields = accept.split('/').collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(anyhow!(utils::ERR_RPC_INVALID_LPOLICY_FORMAT));
        }

        if fields[2] == manifest_digest {
            return Ok(true);
        } else if fields[1] == signer_digest {
            if fields[2] == "*" {
                return Ok(true);
            } else {
                let aliases = fields[2].split(':').collect::<Vec<_>>();
                if aliases.len() != 2 {
                    return Err(anyhow!(utils::ERR_RPC_INVALID_LPOLICY_FORMAT));
                }

                let svn = aliases[1].parse::<u64>()?;
                for (_, value) in itself_aliases.iter() {
                    for val in value {
                        let aliases2 = val.split(':').collect::<Vec<_>>();
                        if aliases2.len() != 2 {
                            return Err(anyhow!(utils::ERR_RPC_INVALID_MALIAS_FORMAT));
                        }

                        let svn2 = aliases2[1].parse::<u64>()?;
                        if aliases2[0] == aliases[0] && svn2 >= svn {
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod unit_test {
    use super::*;
    use crate::container::CStatus;
    use crate::image::{AttestDataValue, Manifest};
    use nix::unistd::Pid;

    fn build_image() -> Image {
        let manifest_json: &str = r#"
        {
            "aliases": {
              "contents": {},
              "self": {
                ".": [
                    "SomeProduct:2",
                    "SomeProduct:1",
                    "SomeProduct:0"
                  ]
              }
            },
            "maxInstances": 0,
            "entrypoint": [],
            "layers": [
                "sha256/8d3ac3489996423f53d6087c81180006263b79f206d3fdec9e66f0e27ceb8759",
                "sha256/fe4b5357dae419c2784d35586ccb721a621ba82756022889b9f49f34b5dd5b06",
                "sha384/8399aa9f39f61aae8e1d1cd4740d851e6c25a66c092ed740812841f56e51db5cefa8fd54c20d2cb0483dab785f92cbbf"
            ],
            "policy": {
              "accepts": [],
              "rejectUnaccepted": true
            }
        }"#;
        let m: Manifest = serde_json::from_str(manifest_json).unwrap();

        Image {
            id: "sha256/b6191c33376247a10b0e93f04039e6dacb2493184cdf4baeaed1d2f633e00b8c/6ab828a50a33f5a21c93e02ecc3d4085af1c0491cec40a80a8b95949871474bf".to_string(),
            hash_algorithm: "sha256".to_string(),
            signer_digest: "b6191c33376247a10b0e93f04039e6dacb2493184cdf4baeaed1d2f633e00b8c".to_string(),
            signer_bytes: Vec::new(),
            manifest_digest: "6ab828a50a33f5a21c93e02ecc3d4085af1c0491cec40a80a8b95949871474bf".to_string(),
            manifest: m,
        }
    }

    fn build_target_image() -> Image {
        let mut target_image = build_image();
        target_image.id =
            "sha256/b6191c33376247a10b0e93f04039e6dacb2493184cdf4baeaed1d2f633e00b8c/34ffdfcaa731a731d163006ce882eb996b166c221e21502d96ed3eb0566295be".to_string();
        target_image.hash_algorithm = "sha256".to_string();
        target_image.signer_digest =
            "b6191c33376247a10b0e93f04039e6dacb2493184cdf4baeaed1d2f633e00b8c".to_string();
        target_image.manifest_digest =
            "34ffdfcaa731a731d163006ce882eb996b166c221e21502d96ed3eb0566295be".to_string();

        target_image
    }

    fn build_target_layer() -> Vec<String> {
        let mut target_layers = Vec::new();
        target_layers
            .push("aea0630882add62e97642017c30106b227e7f925d712da20c019195e87224f6a".to_string());
        target_layers.push("29875cfd4be56c2417ec484ef52c4e08a7c84fe2f6344037785463190b9f3a9231cb8672357735fb82cbded39584a6b5".to_string());
        target_layers.push("abf2d89d8025bd2576914c0925fd1d90dd4b87e5b9453e02fe991a90c50b38b5ed169fedeafaa7a03d5dcdd483e71aa1fa81404da99339a9f145c8956bcc5166".to_string());

        target_layers
    }

    #[test]
    fn test_new() {
        let pod = Pod::new(None);
        assert_eq!(pod.images.len(), 0);
    }

    #[test]
    fn test_add_image() {
        let mut pod = Pod::new(None);
        pod.add_image(build_image());

        assert_eq!(pod.images.len(), 1);
    }

    #[test]
    fn test_get_image_01() {
        let pod = Pod::new(None);

        assert_eq!(pod.get_image("image_id"), None);
    }

    #[test]
    fn test_get_image_02() {
        let mut pod = Pod::new(None);
        let image = build_image();
        let image_clone = image.clone();
        pod.add_image(image);

        assert_eq!(pod.get_image(&image_clone.id), Some(&image_clone));
    }

    #[test]
    fn test_add_container() {
        let mut pod = Pod::new(None);
        pod.add_container(Container {
            id: 1,
            pid: Pid::from_raw(1),
            image_id: String::default(),
            status: CStatus::Running(0),
            exec_path: String::default(),
            envs: None,
            uids: None,
            attest_data: AttestDataValue::NoDataValue {},
            exit_notifier: None,
        });

        assert_eq!(pod.containers.len(), 1);
    }

    #[test]
    fn test_get_container_01() {
        let pod = Pod::new(None);

        assert!(pod.get_container(&1).is_none());
    }

    #[test]
    fn test_get_container_02() {
        let mut pod = Pod::new(None);
        pod.add_container(Container {
            id: 1,
            pid: Pid::from_raw(1),
            image_id: String::default(),
            status: CStatus::Running(0),
            exec_path: String::default(),
            envs: None,
            uids: None,
            attest_data: AttestDataValue::NoDataValue {},
            exit_notifier: None,
        });

        assert!(pod.get_container(&1).is_some());
    }

    #[test]
    fn test_has_alive_container_01() {
        let pod = Pod::new(None);

        assert!(!pod.has_alive_container());
    }

    #[test]
    fn test_has_alive_container_02() {
        let mut pod = Pod::new(None);
        pod.add_container(Container {
            id: 1,
            pid: Pid::from_raw(1),
            image_id: String::default(),
            status: CStatus::Exited(0),
            exec_path: String::default(),
            envs: None,
            uids: None,
            attest_data: AttestDataValue::NoDataValue {},
            exit_notifier: None,
        });

        assert!(!pod.has_alive_container());
    }

    #[test]
    fn test_has_alive_container_03() {
        let mut pod = Pod::new(None);
        pod.add_container(Container {
            id: 1,
            pid: Pid::from_raw(1),
            image_id: String::default(),
            status: CStatus::Running(0),
            exec_path: String::default(),
            envs: None,
            uids: None,
            attest_data: AttestDataValue::NoDataValue {},
            exit_notifier: None,
        });

        assert!(pod.has_alive_container());
    }

    #[test]
    fn test_is_manifest_accepted_001() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.reject_unaccepted = false;

        // no existing bunldes.
        // 'reject_unaccepted' of target image is false.
        // accept in this case.
        {
            let mut pod = Pod::new(None);
            assert!(pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_002() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.reject_unaccepted = true;

        // no existing bunldes.
        // 'reject_unaccepted' of target image is true.
        // accept in this case.
        {
            let mut pod = Pod::new(None);
            assert!(pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_003() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image.manifest.policy.reject_unaccepted = false;

        // 'reject_unaccepted' of target image is false.
        // 'reject_unaccepted' of all the exiting images are false.
        // accept in this case.
        {
            let mut image1 = build_image();
            image1.manifest.policy.reject_unaccepted = false;
            let mut image2 = build_image();
            image2.manifest.policy.reject_unaccepted = false;

            let mut pod = Pod::new(None);
            pod.add_image(image1);
            pod.add_image(image2);

            assert!(pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_004() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image.manifest.policy.reject_unaccepted = false;

        // 'reject_unaccepted' of target image is false.
        // 'reject_unaccepted' of one exiting image is true and its 'accepts' doesn't contain target image.
        // reject in this case.
        {
            let mut image = build_image();
            image.manifest.policy.accepts.clear();
            image.manifest.policy.reject_unaccepted = true;

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(!pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_005() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image.manifest.policy.reject_unaccepted = true;

        // 'reject_unaccepted' of target image is true.
        // 'reject_unaccepted' of one exiting image is true and its 'accepts' doesn't contain target image.
        // reject in this case.
        {
            let mut image = build_image();
            image.manifest.policy.accepts.clear();
            image.manifest.policy.reject_unaccepted = true;

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(!pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_006() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image.manifest.policy.reject_unaccepted = true;

        // 'reject_unaccepted' of existing images are all false.
        // 'reject_unaccepted' of target image is true and its 'accepts' doesn't contain any existing images.
        // reject in this case.
        {
            let mut image = build_image();
            image.manifest.policy.accepts.clear();
            image.manifest.policy.reject_unaccepted = false;

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(!pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_007() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image.manifest.policy.reject_unaccepted = true;

        // 'reject_unaccepted' of target image is true but its 'accepts' contains one existing image.
        // 'reject_unaccepted' of the exiting image is true and its 'accepts' doesn't contain target image.
        // reject in this case.
        {
            let mut image = build_image();
            image.manifest.policy.accepts.clear();
            image.manifest.policy.reject_unaccepted = true;

            target_image.manifest.policy.accepts.push(image.id.clone());

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(!pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_008() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image.manifest.policy.reject_unaccepted = true;

        // 'reject_unaccepted' of target image is true and its 'accepts' doesn't contain any existing images.
        // 'reject_unaccepted' of the exiting image is true but its 'accepts' contains target image.
        // reject in this case.
        {
            let mut image = build_image();
            image.manifest.policy.accepts.clear();
            image.manifest.policy.accepts.push(target_image.id.clone());
            image.manifest.policy.reject_unaccepted = true;

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(!pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_009() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image.manifest.policy.reject_unaccepted = false;

        // 'reject_unaccepted' of target image is false.
        // 'reject_unaccepted' of one exiting image is true but its 'accepts' contains target image.
        // accept in this case.
        {
            let mut image = build_image();
            image.manifest.policy.accepts.clear();
            image.manifest.policy.accepts.push(target_image.id.clone());
            image.manifest.policy.reject_unaccepted = true;

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_010() {
        let mut target_image = build_target_image();

        // 'reject_unaccepted' of target image is true but its 'accepts' contains one existing image.
        // 'reject_unaccepted' of the exiting image is false.
        // accept in this case.
        {
            let mut image = build_image();
            image.manifest.policy.accepts.clear();
            image.manifest.policy.reject_unaccepted = false;

            target_image.manifest.policy.accepts.clear();
            target_image.manifest.policy.accepts.push(image.id.clone());
            target_image.manifest.policy.reject_unaccepted = true;

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_manifest_accepted_011() {
        let mut target_image = build_target_image();

        // 'reject_unaccepted' of target image is true but its 'accepts' contains one existing image.
        // 'reject_unaccepted' of one exiting image is true but its 'accepts' contains target image.
        // accept in this case.
        {
            let mut image = build_image();
            image.manifest.policy.accepts.clear();
            image.manifest.policy.accepts.push(target_image.id.clone());
            image.manifest.policy.reject_unaccepted = true;

            target_image.manifest.policy.accepts.clear();
            target_image.manifest.policy.accepts.push(image.id.clone());
            target_image.manifest.policy.reject_unaccepted = true;

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(pod.is_manifest_accepted(&target_image).unwrap());
        }
    }

    #[test]
    fn test_is_blob_accepted_001() {
        let target_layers = build_target_layer();

        // reject if no bunldes exist.
        {
            let pod = Pod::new(None);
            assert!(!pod.is_blob_accepted(&target_layers));
        }
    }

    #[test]
    fn test_is_blob_accepted_002() {
        let target_layers = build_target_layer();

        // reject if no existing images contain the target layers.
        {
            let mut pod = Pod::new(None);
            pod.add_image(build_image());

            assert!(!pod.is_blob_accepted(&target_layers));
        }
    }

    #[test]
    fn test_is_blob_accepted_003() {
        let target_layers = build_target_layer();

        // accept if at least one of the existing images contains the target layers.
        {
            let mut image = build_image();
            image.manifest.layers.push(
                "aea0630882add62e97642017c30106b227e7f925d712da20c019195e87224f6a".to_string(),
            );

            let mut pod = Pod::new(None);
            pod.add_image(image);

            assert!(pod.is_blob_accepted(&target_layers));
        }
    }

    #[test]
    fn test_has_rejecting_image_01() {
        let mut image = build_image();
        image.manifest.policy.reject_unaccepted = true;

        let mut pod = Pod::new(None);
        pod.add_image(image);

        assert!(pod.has_rejecting_image());
    }

    #[test]
    fn test_has_rejecting_image_02() {
        let mut image = build_image();
        image.manifest.policy.reject_unaccepted = false;

        let mut pod = Pod::new(None);
        pod.add_image(image);

        assert!(!pod.has_rejecting_image());
    }

    #[test]
    fn test_accept_all_existed_images_01() {
        let image1_id = "sha256/*/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";
        let mut image1 = build_image();
        image1.id = image1_id.to_string();
        image1.manifest_digest =
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string();
        image1.manifest.policy.reject_unaccepted = false;

        let image2_id = "sha256/*/d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35";
        let mut image2 = build_image();
        image2.id = image2_id.to_string();
        image2.manifest_digest =
            "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35".to_string();
        image2.manifest.policy.reject_unaccepted = false;

        let mut pod = Pod::new(None);
        pod.add_image(image1);
        pod.add_image(image2);

        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image
            .manifest
            .policy
            .accepts
            .push(image1_id.to_string());
        target_image.manifest.policy.reject_unaccepted = true;

        assert!(!pod.accept_all_existed_images(&target_image).unwrap());
    }

    #[test]
    fn test_accept_all_existed_images_02() {
        let image1_id = "sha256/*/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";
        let mut image1 = build_image();
        image1.id = image1_id.to_string();
        image1.manifest_digest =
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string();
        image1.manifest.policy.reject_unaccepted = false;

        let image2_id = "sha256/*/d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35";
        let mut image2 = build_image();
        image2.id = image2_id.to_string();
        image2.manifest_digest =
            "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35".to_string();
        image2.manifest.policy.reject_unaccepted = false;

        let mut pod = Pod::new(None);
        pod.add_image(image1);
        pod.add_image(image2);

        let mut target_image = build_target_image();
        target_image.manifest.policy.accepts.clear();
        target_image
            .manifest
            .policy
            .accepts
            .push(image1_id.to_string());
        target_image
            .manifest
            .policy
            .accepts
            .push(image2_id.to_string());
        target_image.manifest.policy.reject_unaccepted = true;

        assert!(pod.accept_all_existed_images(&target_image).unwrap());
    }

    #[test]
    fn test_accept_incoming_image_01() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.reject_unaccepted = false;

        let mut image1 = build_image();
        image1.manifest.policy.reject_unaccepted = false;

        let mut image2 = build_image();
        image2.manifest.policy.reject_unaccepted = true;

        let mut pod = Pod::new(None);
        pod.add_image(image1);
        pod.add_image(image2);

        assert!(!pod.accept_incoming_image(&target_image).unwrap());
    }

    #[test]
    fn test_accept_incoming_image_02() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.reject_unaccepted = false;

        let mut image1 = build_image();
        image1.manifest.policy.reject_unaccepted = false;

        let mut image2 = build_image();
        image2.manifest.policy.reject_unaccepted = true;
        image2.manifest.policy.accepts.clear();
        image2.manifest.policy.accepts.push(target_image.id.clone());

        let mut pod = Pod::new(None);
        pod.add_image(image1);
        pod.add_image(image2);

        assert!(pod.accept_incoming_image(&target_image).unwrap());
    }

    #[test]
    fn test_accept_existed_rejecting_images_01() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.reject_unaccepted = true;

        let mut image1 = build_image();
        image1.manifest.policy.reject_unaccepted = false;

        let mut image2 = build_image();
        image2.manifest.policy.reject_unaccepted = false;

        let mut pod = Pod::new(None);
        pod.add_image(image1);
        pod.add_image(image2);

        assert!(!pod.accept_incoming_image(&target_image).unwrap());
    }

    #[test]
    fn test_accept_existed_rejecting_images_02() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.reject_unaccepted = true;

        let mut image = build_image();
        image.manifest.policy.reject_unaccepted = true;

        let mut pod = Pod::new(None);
        pod.add_image(image);

        assert!(!pod.accept_incoming_image(&target_image).unwrap());
    }

    #[test]
    fn test_accept_existed_rejecting_images_03() {
        let mut target_image = build_target_image();
        target_image.manifest.policy.reject_unaccepted = true;

        let mut image = build_image();
        image.manifest.policy.reject_unaccepted = true;
        image.manifest.policy.accepts.push(target_image.id.clone());

        let mut pod = Pod::new(None);
        pod.add_image(image);

        assert!(pod.accept_incoming_image(&target_image).unwrap());
    }

    #[test]
    fn test_accept_image_01() {
        let image = build_image();
        let accepts = vec![
            "sha256/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string(),
        ];

        assert!(accept_image(&accepts, &image).is_err());
    }

    #[test]
    fn test_accept_image_02() {
        let mut image = build_image();
        image.signer_digest =
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string();
        let accepts = vec![
            "sha256/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b/Product"
                .to_string(),
        ];

        assert!(accept_image(&accepts, &image).is_err());
    }

    #[test]
    fn test_accept_image_03() {
        let mut image = build_image();
        image.signer_digest =
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string();
        image
            .manifest
            .aliases
            .itself
            .insert(".".to_string(), vec!["Product".to_string()]);
        let accepts = vec![
            "sha256/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b/Product:1"
                .to_string(),
        ];

        assert!(accept_image(&accepts, &image).is_err());
    }

    #[test]
    fn test_accept_image_04() {
        let mut image = build_image();
        image.manifest_digest =
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string();
        let accepts = vec![
            "sha256/*/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string(),
        ];

        assert!(accept_image(&accepts, &image).unwrap());
    }

    #[test]
    fn test_accept_image_05() {
        let mut image = build_image();
        image.signer_digest =
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string();
        let accepts = vec![
            "sha256/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b/*".to_string(),
        ];

        assert!(accept_image(&accepts, &image).unwrap());
    }

    #[test]
    fn test_accept_image_06() {
        let mut image = build_image();
        image.signer_digest =
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string();
        image
            .manifest
            .aliases
            .itself
            .insert(".".to_string(), vec!["Product:0".to_string()]);
        let accepts = vec![
            "sha256/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b/Product:1"
                .to_string(),
        ];

        assert!(!accept_image(&accepts, &image).unwrap());
    }

    #[test]
    fn test_accept_image_07() {
        let mut image = build_image();
        image.signer_digest =
            "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b".to_string();
        image.manifest.aliases.itself.insert(
            ".".to_string(),
            vec!["Product:0".to_string(), "Product:1".to_string()],
        );
        let accepts = vec![
            "sha256/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b/Product:1"
                .to_string(),
        ];

        assert!(accept_image(&accepts, &image).unwrap());
    }
}

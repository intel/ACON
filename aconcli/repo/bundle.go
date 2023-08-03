// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"aconcli/config"
	"aconcli/cryptoutil"
)

type Bundle struct {
	path string
}

func NewBundle(path string) *Bundle {
	return &Bundle{path}
}

func (b *Bundle) Digest() ([]byte, error) {
	hashAlgo, err := cryptoutil.GetHashAlgoFromCert(b.Cert())
	if err != nil {
		return nil, fmt.Errorf("cannot get bundle digest: %v", err)
	}
	m := b.Manifest()
	content, err := os.ReadFile(filepath.Clean(m))
	if err != nil {
		return nil, fmt.Errorf("bundle digest: cannot read manifest file %s: %v", m, err)
	}
	content, err = canonicalJson(content)
	if err != nil {
		return nil, fmt.Errorf("bundle digest: cannot canonical manifest %s: %v", m, err)
	}
	digest, err := cryptoutil.BytesDigest(content, hashAlgo)
	if err != nil {
		return nil, fmt.Errorf("bundle digest: cannot get digest for manifest %s: %v", m, err)
	}
	return digest, nil
}

func (b *Bundle) SignerDigest() ([]byte, string, error) {
	return cryptoutil.GetCertDigest(b.Cert())
}

func (b *Bundle) Manifest() string {
	return filepath.Join(b.path, config.ManifestFileName)
}

func (b *Bundle) Cert() string {
	return filepath.Join(b.path, config.CertFileName)
}

func (b *Bundle) Sig() string {
	return filepath.Join(b.path, config.SignatureFileName)
}

func (b *Bundle) Key() string {
	return filepath.Join(b.path, config.PrivKeyFileName)
}

func (b *Bundle) IsManifestUpdated() bool {
	digest, err := b.Digest()
	if err != nil {
		return false
	}
	dirname := filepath.Base(b.path)
	return dirname == hex.EncodeToString(digest)
}

func (b *Bundle) IsSignatureValid() bool {
	sig, err := os.ReadFile(b.Sig())
	if err != nil {
		return false
	}
	content, err := os.ReadFile(b.Manifest())
	if err != nil {
		return false
	}
	content, err = canonicalJson(content)
	if err != nil {
		return false
	}
	return cryptoutil.Verify(content, sig, b.Cert())
}

func (b *Bundle) Remove() error {
	return os.RemoveAll(b.path)
}

func (b *Bundle) Layers() ([]string, error) {
	mfile := b.Manifest()
	content, err := os.ReadFile(filepath.Clean(mfile))
	if err != nil {
		return nil, fmt.Errorf("get bundle layers: cannot read manifest %s: %v", mfile, err)
	}
	w := Workload{}
	if err := json.Unmarshal(content, &w); err != nil {
		return nil, fmt.Errorf("get bundle layers: cannot unmarshal manifest %s: %v", mfile, err)
	}
	return w.Layer, nil
}

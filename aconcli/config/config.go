// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package config

const (
	RepoDirName        = ".acon"
	BlobDirName        = "blobs"
	BlobExtension      = ".tar"
	PrimaryHashAlgo    = "sha384"
	PrimaryHashAlgoLen = 96
	DockerHashAlgo     = "sha256"
	ManifestDirName    = "manifests"
	ManifestFileName   = "acon.json"
	CertFileName       = "signer.cer"
	PrivKeyFileName    = "private_key.pem"
	SignatureFileName  = "signature"
	ShortHashLen       = 12
	DefaultCapSize     = 0x20000
	AconVmPrefix       = "aconvm-"
	AconVmEnvTag       = "__ACONVM="
)

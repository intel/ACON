// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cryptoutil

import (
	"crypto"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

type hashAlgoDescriptor struct {
	name string
	algo crypto.Hash
}

var (
	hashAlgoSha384 = hashAlgoDescriptor{"sha384", crypto.SHA384}
	hashAlgoSha512 = hashAlgoDescriptor{"sha512", crypto.SHA512}
	supportedHash  = []hashAlgoDescriptor{hashAlgoSha384, hashAlgoSha512}

	hashAlgoDescriptorMap = map[string]hashAlgoDescriptor{
		"SHA384-RSA":    hashAlgoSha384,
		"SHA512-RSA":    hashAlgoSha512,
		"SHA384-RSAPSS": hashAlgoSha384,
		"SHA512-RSAPSS": hashAlgoSha512,
		"ECDSA-SHA384":  hashAlgoSha384,
		"ECDSA-SHA512":  hashAlgoSha512,
		"Ed25519":       hashAlgoSha512,
	}
)

func genericHash(data []byte, hash crypto.Hash) ([]byte, error) {
	if !hash.Available() {
		return nil, errors.New("cryptoutil: hash algo unavailable")
	}
	h := hash.New()
	h.Write(data)
	return h.Sum(nil), nil
}

func parseCertFile(certfile string) ([]byte, error) {
	dat, err := ioutil.ReadFile(filepath.Clean(certfile))
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(dat)
	if block == nil {
		return rest, nil
	} else if block.Type != "CERTIFICATE" {
		return nil, errors.New("cryptoutil: Certificate PEM block not found")
	} else {
		return block.Bytes, nil
	}
}

func GetHashAlgoFromCert(certfile string) (string, error) {
	derBytes, err := parseCertFile(certfile)
	if err != nil {
		return "", err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return "", err
	}

	sigAlgoStr := cert.SignatureAlgorithm.String()
	hStr := hashAlgoDescriptorMap[sigAlgoStr].name
	return hStr, nil
}

func GetCertDigest(certfile string) ([]byte, string, error) {
	derBytes, err := parseCertFile(certfile)
	if err != nil {
		return nil, "", err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, "", err
	}

	sigAlgoStr := cert.SignatureAlgorithm.String()
	hStr := hashAlgoDescriptorMap[sigAlgoStr].name
	hAlgo := hashAlgoDescriptorMap[sigAlgoStr].algo

	digest, err := genericHash(derBytes, hAlgo)
	if err != nil {
		return nil, "", err
	}
	return digest, hStr, nil
}

func getHashAlgo(algo string) (hashAlgo crypto.Hash, err error) {
	for _, h := range supportedHash {
		if h.name == algo {
			hashAlgo = h.algo
			err = nil
			return
		}
	}
	err = errors.New("cryptoutil: Unknown hash algorithm")
	return
}

func FileDigest(path, algo string) ([]byte, error) {
	hashAlgo, err := getHashAlgo(algo)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return genericHash(data, hashAlgo)
}

func BytesDigest(data []byte, algo string) ([]byte, error) {
	hashAlgo, err := getHashAlgo(algo)
	if err != nil {
		return nil, err
	}

	return genericHash(data, hashAlgo)
}

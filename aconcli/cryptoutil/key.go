// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"path/filepath"
	"strings"
)

// Attemp to parse the given private key DER block.
// Try PKCS#1, PKCS#8 and SEC1 EC private keys.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("cryptoutil: Unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("cryptoutil: Failed to parse private key")
}

// Parse the private key file in PEM format to DER block
func parsePrivateKeyPEMFile(keyFile string) ([]byte, error) {
	keyPEMBlock, err := ioutil.ReadFile(filepath.Clean(keyFile))
	if err != nil {
		return nil, err
	}

	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			return nil, errors.New("cryptoutil: Failed to parse key PEM data")
		}

		if x509.IsEncryptedPEMBlock(keyDERBlock) {
			return nil, errors.New("cryptoutil: Encrypted private key Not supported")
		}

		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, "PRIVATE KEY") {
			break
		}
	}
	return keyDERBlock.Bytes, nil
}

func verify(certDer []byte, privKey crypto.PrivateKey) (err error) {
	x509Cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			err = errors.New("cryptoutil: private key type does not match public key type")
			return
		}
		if pub.N.Cmp(priv.N) != 0 {
			err = errors.New("cryptoutil: private key does not match public key")
			return
		}
	case *ecdsa.PublicKey:
		priv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			err = errors.New("cryptoutil: private key type does not match public key type")
			return

		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			err = errors.New("cryptoutil: private key does not match public key")
			return
		}
	case ed25519.PublicKey:
		priv, ok := privKey.(ed25519.PrivateKey)
		if !ok {
			err = errors.New("cryptoutil: private key type does not match public key type")
			return
		}
		equal := pub.Equal(priv.Public())
		if !equal {
			err = errors.New("cryptoutil: private key does not match public key")
			return
		}
	default:
		err = errors.New("cryptoutil: unknown public key algorithm")
		return
	}
	return
}

func Sign(message []byte, certFile, keyFile string) ([]byte, error) {
	derBlock, err := parsePrivateKeyPEMFile(keyFile)
	if err != nil {
		return nil, err
	}

	privKey, err := parsePrivateKey(derBlock)
	if err != nil {
		return nil, err
	}

	hash, err := GetHashAlgoFromCert(certFile)
	if err != nil {
		return nil, err
	}

	certDer, err := parseCertFile(certFile)
	if err != nil {
		return nil, err
	}

	if err := verify(certDer, privKey); err != nil {
		return nil, err
	}

	switch privKey := privKey.(type) {
	case *rsa.PrivateKey:
		hashAlgo, err := getHashAlgo(hash)
		if err != nil {
			return nil, err
		}
		digest, err := genericHash(message, hashAlgo)
		if err != nil {
			return nil, err
		}
		return rsa.SignPKCS1v15(rand.Reader, privKey, hashAlgo, digest)

	case *ecdsa.PrivateKey:
		hashAlgo, err := getHashAlgo(hash)
		if err != nil {
			return nil, err
		}
		digest, err := genericHash(message, hashAlgo)
		if err != nil {
			return nil, err
		}
		return ecdsa.SignASN1(rand.Reader, privKey, digest)

	case ed25519.PrivateKey:
		return ed25519.Sign(privKey, message), nil

	default:
		return nil, errors.New("cryptoutil: Unknown private key type")
	}
}

func Verify(message, sig []byte, certFile string) bool {

	certDer, err := parseCertFile(certFile)
	if err != nil {
		return false
	}

	hash, err := GetHashAlgoFromCert(certFile)
	if err != nil {
		return false
	}

	x509Cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return false
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		hashAlgo, err := getHashAlgo(hash)
		if err != nil {
			return false
		}
		digest, err := genericHash(message, hashAlgo)
		if err != nil {
			return false
		}
		err = rsa.VerifyPKCS1v15(pub, hashAlgo, digest, sig)
		return err == nil

	case *ecdsa.PublicKey:
		hashAlgo, err := getHashAlgo(hash)
		if err != nil {
			return false
		}
		digest, err := genericHash(message, hashAlgo)
		if err != nil {
			return false
		}
		return ecdsa.VerifyASN1(pub, digest, sig)

	case ed25519.PublicKey:
		return ed25519.Verify(pub, message, sig)

	default:
		return false
	}
}

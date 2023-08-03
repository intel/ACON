// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
)

var (
	dockerImageId    string
	manifestFile     string
	privFile         string
	certFile         string
	sigFile          string
	releaseDir       string
	targetDir        string
	env              []string
	cid              uint32
	timeout          uint64
	supportHashAlgo  = []string{"sha384", "sha512"}
	errorNoRepoFound = errors.New("No ACON repository found. May use 'aconcli init' to create one")
	errorRepoExists  = errors.New("ACON repository already exists")
)

func canonicalJson(data []byte) ([]byte, error) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

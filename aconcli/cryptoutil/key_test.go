// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cryptoutil

import (
	"testing"
)

func TestSignVerify(t *testing.T) {
	message := []byte("hello, ACON!")
	sig, err := Sign(message,
		"../testdata/set2/cert.der",
		"../testdata/set2/priv.pem")
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(message, sig, "../testdata/set2/cert.der") {
		t.Errorf("Verify failed")
	}
}

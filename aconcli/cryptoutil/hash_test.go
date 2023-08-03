// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cryptoutil

import (
	"crypto"
	"encoding/hex"
	"testing"
)

type matchFileDigestTest struct {
	path, algo, want string
}

var matchFileDigestTests = []matchFileDigestTest{
	{"../testdata/set1/cert.der",
		"sha384",
		"fccdc13f89825ca910902e7cf050f280399e106074efd9fb43bd2e8939c605225eb7157e0383f61883e7454fde2ba1c4",
	},
	{"../testdata/set1/cert.der",
		"sha512",
		"7ccc0595461cb3be60c43bcc3759b06c6b5a9b0f4b911d1f4eab5faf9e04893a6742b37d48c8ee66659877b1894ddb66618d4fe4dae742e78464fd3ad66c199b",
	},
}

func TestFileDigest(t *testing.T) {
	for _, test := range matchFileDigestTests {
		d, err := FileDigest(test.path, test.algo)
		if err != nil {
			t.Fatalf("FileDigest(%q, %q): %v", test.path, test.algo, err)
		}

		got := hex.EncodeToString(d)
		if got != test.want {
			t.Errorf("FileDigest(%q, %q) = %v, want %v", test.path, test.algo, got, test.want)
		}
	}
}

type matchGetCertDigestTest struct {
	path, wantAlgo, wantDigest string
}

var matchGetCertDigestTests = []matchGetCertDigestTest{
	{"../testdata/set1/cert.der",
		"sha384",
		"fccdc13f89825ca910902e7cf050f280399e106074efd9fb43bd2e8939c605225eb7157e0383f61883e7454fde2ba1c4",
	},
	{"../testdata/set2/cert.der",
		"sha384",
		"7ec795c3fe89687d4514a1e4f95b2421012fd0b877eba9d5d5f33a1314fe7e10a5b38b0890d890df59b716f55f41e2ff",
	},
}

func TestGetCertDigest(t *testing.T) {
	for _, test := range matchGetCertDigestTests {
		d, a, err := GetCertDigest(test.path)
		if err != nil {
			t.Errorf("GetCertDigest(%q): %v", test.path, err)
		}

		if a != test.wantAlgo {
			t.Errorf("GetCertDigest(%q), got %q, want %q", test.path, a, test.wantAlgo)
		}

		got := hex.EncodeToString(d)
		if got != test.wantDigest {
			t.Errorf("GetCertDigest(%q), got %v, want %v", test.path, got, test.wantDigest)
		}
	}
}

type matchGetHashAlgoFromCertTest struct {
	path, want string
}

var matchGetHashAlgoFromCertTests = []matchGetHashAlgoFromCertTest{
	{"../testdata/set1/cert.der",
		"sha384",
	},
	{"../testdata/set2/cert.der",
		"sha384",
	},
}

func TestGetHashAlgoFromCert(t *testing.T) {
	for _, test := range matchGetHashAlgoFromCertTests {
		h, err := GetHashAlgoFromCert(test.path)
		if err != nil {
			t.Errorf("GetHashAlgoFromCert(%q): %v", test.path, err)
		}

		if h != test.want {
			t.Errorf("GetHashAlgoFromCert(%q), got %q, want %q", test.path, h, test.want)
		}
	}
}

func Test_getHashAlgo(t *testing.T) {
	algo, err := getHashAlgo("sha384")
	if err != nil || algo != crypto.SHA384 {
		t.Errorf("getHashAlgo(\"sha384\")")
	}

	algo, err = getHashAlgo("sha512")
	if err != nil || algo != crypto.SHA512 {
		t.Errorf("getHashAlgo(\"sha512\")")
	}

	_, err = getHashAlgo("unknown")
	if err == nil {
		t.Errorf("getHashAlgo(\"unknown\")")
	}
}

// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aconcli/config"
)

const (
	repoTestPath = "../testdata/test_repo"
	repoPath     = repoTestPath + "/" + config.RepoDirName
)

var testingR *Repo

func TestMain(m *testing.M) {

	if err := os.Mkdir(repoPath, 0750); err != nil {
		os.Exit(-1)
	}
	r, err := FindRepo(repoTestPath)
	if err != nil {
		os.Exit(-1)
	}
	testingR = r
	exitVal := m.Run()
	os.RemoveAll(repoPath)
	os.Exit(exitVal)
}

func TestFindRepo(t *testing.T) {
	if !strings.HasSuffix(testingR.path, "testdata/test_repo/"+config.RepoDirName) {
		t.Errorf("FindRepo: got %s", testingR.path)
	}
}

func TestCommitBlob(t *testing.T) {
	repoLayers := []struct {
		name         string
		digestSha256 string
		digestSha384 string
	}{
		{
			"acon_image_layer0",
			"26a89af864a0f616a1ad8ed92788933582be59caa06c34d40e1b24cfba1d7e1d",
			"de9d9395ea0a434af3ffd9ae13c9ecf0b8a209881a7a6785b5f5427c0b613bab5c8dbb37bb577ae484cf9d90b13ef5f3",
		},
		{
			"acon_image_layer1",
			"e73175481c5741e0fedf323ec2b66bcbb2cbc10a6be0f3eca03e6a8e2b4a1970",
			"86a35cf623699eaa741712b80d342a7aa350ceb445aaf7c550199737635619e25038027a72db005672ba30f47ea39204",
		},
		{
			"acon_image_layer3",
			"7933ca5b8fadb74a08c558b3c560ce2690ee767df7ac6fa8aedfb3552108d6ea",
			"badd0ba0ce62b587b507ad0d4451040f7c7d3bbbb81a572c6723f8cf8b7b081ea81b6b7c81cbfd31fa934ba77c809365",
		},
	}
	blobs := make([][]byte, len(repoLayers))
	diffIds := make([]string, len(repoLayers))

	for i, layer := range repoLayers {
		blobs[i], _ = os.ReadFile(filepath.Join(repoTestPath, layer.name))
		diffIds[i] = "sha256:" + layer.digestSha256
	}
	err := testingR.CommitBlob(blobs, diffIds)
	if err != nil {
		t.Fatal(err)
	}

	for _, layer := range repoLayers {
		primaryDigest, err := testingR.PrimaryDigest("sha256:" + layer.digestSha256)
		if err != nil {
			t.Fatal(err)
		}
		want := "sha384/" + layer.digestSha384
		if primaryDigest != want {
			t.Errorf("repo.PrimaryDigest, want: %s, got: %s", want, primaryDigest)
		}
	}
}

func TestCommitManifest(t *testing.T) {
	err := testingR.CommitManifest(filepath.Join(repoTestPath, config.ManifestFileName),
		"../testdata/set2/cert.der",
		"../testdata/set2/priv.pem")
	if err != nil {
		t.Fatal(err)
	}
}

func TestFindBundle(t *testing.T) {
	bundleByName, err := testingR.FindBundle(filepath.Join(repoTestPath, config.ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}

	bundleByHash, err := testingR.FindBundle("986f928e2e8c")
	if err != nil {
		t.Fatal(err)
	}

	if bundleByName.path != bundleByHash.path {
		t.Fatal(err)
	}
}

func TestBundle(t *testing.T) {
	bundle, err := testingR.FindBundle(filepath.Join(repoTestPath, config.ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}

	if !bundle.IsManifestUpdated() {
		t.Error(err)
	}

	if !bundle.IsSignatureValid() {
		t.Error(err)
	}

	layers, err := bundle.Layers()
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"sha384/de9d9395ea0a434af3ffd9ae13c9ecf0b8a209881a7a6785b5f5427c0b613bab5c8dbb37bb577ae484cf9d90b13ef5f3",
		"sha384/86a35cf623699eaa741712b80d342a7aa350ceb445aaf7c550199737635619e25038027a72db005672ba30f47ea39204",
		"sha384/badd0ba0ce62b587b507ad0d4451040f7c7d3bbbb81a572c6723f8cf8b7b081ea81b6b7c81cbfd31fa934ba77c809365",
	}

	if len(layers) != len(want) {
		t.Fatalf("bundle.Layers: want %v, got %v", want, layers)
	}

	for i := range want {
		if layers[i] != want[i] {
			t.Errorf("bundle.Layers: layer %d, want %v, got %v", i, want[i], layers[i])
		}
	}
}

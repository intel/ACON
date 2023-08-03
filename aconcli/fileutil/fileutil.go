// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package fileutil

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type m struct {
	Layers []string `json:"Layers"`
}

func UntarBlob(r io.Reader) ([]string, map[string][]byte, error) {
	layerData := make(map[string][]byte)
	var layerString []string
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		switch {
		case err == io.EOF:
			return layerString, layerData, nil

		case err != nil:
			return nil, nil, err

		case header == nil:
			continue
		}

		switch header.Typeflag {
		case tar.TypeReg:
			if strings.HasSuffix(header.Name, ".tar") {
				data, err := ioutil.ReadAll(tr)
				if err != nil {
					return nil, nil, err
				}
				layerData[header.Name] = data
			}
			if header.Name == "manifest.json" {
				data, err := ioutil.ReadAll(tr)
				if err != nil {
					return nil, nil, err
				}
				var manifest []m
				err = json.Unmarshal(data, &manifest)
				if err != nil {
					return nil, nil, err
				}
				layerString = manifest[0].Layers
			}
		}
	}
}

func Tar(tarFilePath string, filePaths []string, fileNameFilter func(string) string) error {
	tarFile, err := os.Create(filepath.Clean(tarFilePath))
	if err != nil {
		return fmt.Errorf("fail to create tar file %v, err %v", tarFilePath, err)

	}
	defer tarFile.Close()

	tarWriter := tar.NewWriter(tarFile)
	defer tarWriter.Close()

	for _, filePath := range filePaths {
		err := addFileToTar(filePath, tarWriter, fileNameFilter)
		if err != nil {
			return fmt.Errorf("fail to add file %v, err %v", filePath, err)
		}
	}

	return nil
}

func addFileToTar(filePath string, tarWriter *tar.Writer, nameFilter func(string) string) error {
	file, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return fmt.Errorf("fail to open file %v, err %v", filePath, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("fail to stat file %v, err %v", filePath, err)
	}

	if nameFilter != nil {
		filePath = nameFilter(filePath)
	}

	header := &tar.Header{
		Name:    filePath,
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	err = tarWriter.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("fail to write header for file %v, err %v", filePath, err)
	}

	_, err = io.Copy(tarWriter, file)
	if err != nil {
		return fmt.Errorf("fail to copy file %v into tarball, err %v", filePath, err)
	}

	return nil
}

func Untar(dst string, r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err

		case header == nil:
			continue
		}

		target := filepath.Join(dst, header.Name)
		if !strings.HasPrefix(filepath.Clean(target), dst) {
			return fmt.Errorf("invalid path: %s", target)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err == os.ErrNotExist {
				if err := os.MkdirAll(target, 0750); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			if _, err := os.Stat(target); err == nil {
				continue
			}
			dir := filepath.Dir(target)
			if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
				if err := os.MkdirAll(dir, 0750); err != nil {
					return err
				}
			}
			f, err := os.OpenFile(filepath.Clean(target), os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				return err
			}
			if _, err := io.CopyN(f, tr, header.Size); err != nil {
				return err
			}
			f.Close()
		}
	}
}

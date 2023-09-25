// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"aconcli/config"
	"aconcli/repo"
	"github.com/spf13/cobra"
)

var notrunc bool

var lsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List ACON images in the repository",
	Long: `
List current ACON image status in the ACON repository`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return lsManifest()
	},
}

var manifestStatusTitile = []string{
	"NAME",
	"STATUS",
	"VALID",
	"DIGEST",
	"SIGNER DIGEST",
	"KEY STATUS",
	"SIG VALID"}

func isSymlinkBroken(path string) bool {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return true
	}
	_, err = os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	return false
}

func filetype(path string) (string, string) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "invalid", path
	}

	switch mode := fi.Mode(); {
	case mode.IsRegular():
		return "regular", path

	case mode&fs.ModeSymlink != 0:
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "broken symlink", path
		} else if isSymlinkBroken(path) {
			return "broken symlink", target
		} else {
			return "symlink", target
		}
	default:
		return "invalid", path
	}
}

func bundleStatus(b *repo.Bundle) []string {
	st := make([]string, len(manifestStatusTitile))

	mpath := b.Manifest()
	manifestType, manifestPath := filetype(mpath)
	currAbs, _ := filepath.Abs(".")
	rel, _ := filepath.Rel(currAbs, manifestPath)
	st[0] = rel
	st[1] = manifestType
	st[2] = strconv.FormatBool(b.IsManifestUpdated())
	digest, err := b.Digest()
	if err != nil {
		st[3] = "INVALID"
	} else if notrunc {
		st[3] = hex.EncodeToString(digest)
	} else {
		st[3] = hex.EncodeToString(digest)[:config.ShortHashLen]
	}
	digest, _, err = b.SignerDigest()
	if err != nil {
		st[4] = "INVALID"
	} else if notrunc {
		st[4] = hex.EncodeToString(digest)
	} else {
		st[4] = hex.EncodeToString(digest)[:config.ShortHashLen]
	}
	kpath := b.Key()
	ktype, _ := filetype(kpath)
	st[5] = ktype
	st[6] = strconv.FormatBool(b.IsSignatureValid())
	return st
}

func getFormat(mtuples [][]string) []string {
	lens := make([]int, len(mtuples[0]))
	for _, mtuple := range mtuples {
		for i, e := range mtuple {
			length := len(e)
			if length > lens[i] {
				lens[i] = length
			}
		}
	}
	extra := 4
	var format []string
	for _, length := range lens {
		// something like %-9v, left-justifies the string
		f := fmt.Sprintf("%%-%dv", length+extra)
		format = append(format, f)
	}
	return format
}

func printManifestStatus(format []string, mtuple []string) {
	for i := range format {
		fmt.Fprintf(os.Stdout, format[i], mtuple[i])
	}
	fmt.Fprintf(os.Stdout, "\n")
}

func printManifests(bundles []*repo.Bundle) {
	allBundleStatus := [][]string{manifestStatusTitile}
	for _, b := range bundles {
		status := bundleStatus(b)
		allBundleStatus = append(allBundleStatus, status)
	}
	format := getFormat(allBundleStatus)
	for _, s := range allBundleStatus {
		printManifestStatus(format, s)
	}
}

func lsManifest() error {
	startingDir := "."
	if targetDir != "" {
		startingDir = targetDir
	}
	r, err := repo.FindRepo(startingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "List Manifest: %v\n", err)
		return err
	}
	bundles, err := r.AllBundles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "List Manifest: cannot get manifests to show: %v\n", err)
		return err
	}
	printManifests(bundles)
	return nil
}

func init() {
	rootCmd.AddCommand(lsCmd)
	lsCmd.Flags().BoolVar(&notrunc, "no-trunc", false, "Don't truncate output for hash digest")
}

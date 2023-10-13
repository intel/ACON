// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"aconcli/repo"
	"github.com/spf13/cobra"
)

var prune bool

var rmCmd = &cobra.Command{
	Use:     "rm manifest...",
	Short:   "Remove ACON images",
	GroupID: "image",
	Long: `
Remove one or more ACON images/manifests from their ACON image repos.

Manifests can be specified either by paths or by hash digests, which can be
obtained by 'aconcli ls'.

'aconcli rm' also removes certficate and signature files associated with the
specified manifests, but it does NOT remove file system layers as they may be
shared among multiple ACON images/manifests. 'aconcli prune' can be used to
clean up unreferenced file system layers.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return removeManifest(args)
	},
}

func findSingleMatch(dir, id string) (string, error) {
	pattern := filepath.Join(dir, id+"*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", err
	}

	numMatch := len(matches)
	if numMatch == 1 {
		return matches[0], nil
	}

	return "", errors.New("No single match")
}

func isHashId(id string) bool {
	for _, hashAlgo := range supportHashAlgo {
		if strings.HasPrefix(id, hashAlgo+":") {
			return true
		}
	}
	return false
}

func removeManifest(ids []string) error {
	startingDir := "."
	if targetDir != "" {
		startingDir = targetDir
	}

	r, err := repo.FindRepo(startingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Remove Manifest: %v\n", err)
		return err
	}

	bundles, err := r.AllBundles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Remove Manifest: cannot get all manifests: %v\n", err)
		return err
	}

	var returnE error
	partialE := errors.New("work not fully completed")

	if prune {
		for _, b := range bundles {
			f := b.Manifest()
			fi, err := os.Lstat(f)
			if err != nil {
				continue
			}
			if fi.Mode()&fs.ModeSymlink != 0 && isSymlinkBroken(f) {
				if err := b.Remove(); err != nil {
					fmt.Fprintf(os.Stderr, "Remove Manifest: %s contains broken symlink, but failed to remove: %v\n", f, err)
					returnE = partialE
				}
			}
		}
	}

	for _, id := range ids {
		if err := r.RemoveBundle(id); err != nil {
			fmt.Fprintf(os.Stderr, "Remove Manifest: cannot remove manifest %s: %v\n", id, err)
			returnE = partialE
		}
	}

	return returnE
}

func init() {
	rootCmd.AddCommand(rmCmd)
	rmCmd.Flags().BoolVarP(&prune, "prune", "p", false,
		"also remove the manifest files whose symbolic link are currently broken")
}

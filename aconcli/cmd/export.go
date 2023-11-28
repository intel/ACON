// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"aconcli/repo"

	"github.com/spf13/cobra"
)

var ignoreSig bool

var releaseCmd = &cobra.Command{
	Use:     "export manifest",
	Short:   "Export ACON images into tarballs",
	GroupID: "image",
	Long: `
Export an ACON image (specified as the path to its manifest) into a tarball.

An ACON image is comprised of a manifest file, a signature file (containing
the digital signature of the manifest), a certificate file (for verifying the
signature), and the file system layers referenced by the manifest. 'aconcli
export' packages all those files in a single tarball, which can then be
imported into a different ACON image repo by 'aconcli import'.

NOTE1: Only those file system layers referenced by digests will be exported,
while others referenced by aliases will NOT be exported.

NOTE2: ACON images that the specified manifest depends on (i.e., images
defining aliases that have been referenced by the specified manifest) will NOT
be exported.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return exportBundles(args)
	},
}

func exportBundles(args []string) error {
	if ignoreSig {
		return fmt.Errorf("flag '--ignoresig' is yet to be implemented")
	}

	manifestFile := args[0]
	startingDir := filepath.Dir(manifestFile)
	if targetDir != "" {
		startingDir = targetDir
	}
	r, err := repo.FindRepo(startingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Export Bundle: %v\n", err)
		return err
	}

	if err := r.ExportBundle(manifestFile, exportName); err != nil {
		fmt.Fprintf(os.Stderr, "Export Bundle: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(releaseCmd)
	releaseCmd.Flags().BoolVarP(&ignoreSig, "ignoresig", "", false,
		"ignoring missing signature file while exporting image (unimplemented)")
	releaseCmd.Flags().StringVarP(&exportName, "output", "o", "",
		"output tarball file name")
	releaseCmd.MarkFlagRequired("output")
}

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
	Use:   "export MANIFEST",
	Short: "Export the specified ACON images into a tarball file",
	Long: `
Export the specified ACON workloads into a tarball file, including the
workload manifests, the certificates, the signatures and their file
system layers`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return exportBundles(args)
	},
}

func exportBundles(args []string) error {
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

	if err := r.ExportBundle(manifestFile, releaseDir); err != nil {
		fmt.Fprintf(os.Stderr, "Export Bundle: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(releaseCmd)
	releaseCmd.Flags().BoolVarP(&ignoreSig, "ignoresig", "", false,
		"ignoring missing signature file")
	releaseCmd.Flags().StringVarP(&releaseDir, "output", "o", "",
		"output directory for the release materials")
	releaseCmd.MarkFlagRequired("output")
}

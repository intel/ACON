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
	Use:   "export <manifest-file>",
	Short: "Export the ACON image into a tarball file",
	Long: `
Export the ACON image corresponding to the specified manifest file into
a tarball. The image includes a manifest file, a signature file, a
certificate file to verify the signature, and the file system layers
of the image. The images on which the specified image depends will not
be exported`,
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

	if err := r.ExportBundle(manifestFile, exportName); err != nil {
		fmt.Fprintf(os.Stderr, "Export Bundle: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(releaseCmd)
	releaseCmd.Flags().BoolVarP(&ignoreSig, "ignoresig", "", false,
		"ignoring missing signature file while exporting image")
	releaseCmd.Flags().StringVarP(&exportName, "output", "o", "",
		"name of the output tarball file to hold the exported image")
	releaseCmd.MarkFlagRequired("output")
}

// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"aconcli/repo"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import <tarball file>...",
	Short: "Import ACON images into the ACON repository",
	Long: `
Import existing ACON images represented by the specified tarballs into
the ACON repositoy. Imported images will be referenced during alias
substitution process performed by 'aconcli alias-substitute' subcommand`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return importManifest(args)
	},
}

func importManifest(args []string) error {
	startingDir := "."
	if targetDir != "" {
		startingDir = targetDir
	}
	r, err := repo.FindRepo(startingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Import Manifest: %v\n", err)
		return err
	}

	if err := r.ImportBundle(args); err != nil {
		fmt.Fprintf(os.Stderr, "Import Manifest: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(importCmd)
}

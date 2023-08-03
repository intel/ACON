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
	Use:   "import TARBALL ...",
	Short: "Import ACON images",
	Long: `
Import existing ACON images. These imported materials
can be used later to do alias substitution.`,
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

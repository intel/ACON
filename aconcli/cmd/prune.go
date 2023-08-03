// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"aconcli/repo"
	"github.com/spf13/cobra"
)

var pruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Prune unused file system layers",
	Long: `
Prune unused file system layers from the ACON repository`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return pruneBlobs()
	},
}

func pruneBlobs() error {
	startingDir := "."
	if targetDir != "" {
		startingDir = targetDir
	}
	r, err := repo.FindRepo(startingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Prune: %v\n", err)
		return err
	}

	if err := r.Prune(); err != nil {
		fmt.Fprintf(os.Stderr, "Prune: %v\n", err)
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(pruneCmd)
}

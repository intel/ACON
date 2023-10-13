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

var substituteAll bool

var aliasCmd = &cobra.Command{
	Use:     "alias-substitute manifest",
	Short:   "Substitute file system layer digests with aliases",
	GroupID: "image",
	Long: `
Substitute digests of file system layers in the specified ACON image manifest
with aliases defined in ACON images/manifests stored in the same ACON image
repo where the specified manifest resides.

The ACON image repo path is implied by the manifest file path.

By default, only signed images/manifests are searched for alias definitions
unless '-a' is specified, in which case both signed and unsigned manifests are
searched.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return aliasSubstitute(args)
	},
}

func aliasSubstitute(args []string) error {
	manifestFile = args[0]
	startingDir := filepath.Dir(manifestFile)
	if targetDir != "" {
		startingDir = targetDir
	}
	r, err := repo.FindRepo(startingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Alias Substitution: %v\n", err)
		return err
	}

	var filter func(*repo.Bundle) bool
	if !substituteAll {
		filter = func(b *repo.Bundle) bool {
			return b.IsSignatureValid()
		}
	}
	if err := r.Alias(manifestFile, filter); err != nil {
		fmt.Fprintf(os.Stderr, "Alias Substitution: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(aliasCmd)
	aliasCmd.Flags().BoolVarP(&substituteAll, "all", "a", false,
		"search both signed and unsigned manifests for alias definitions")
}

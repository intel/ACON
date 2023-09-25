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

var resign bool = false

var signCmd = &cobra.Command{
	Use:   "sign <manifest file>",
	Short: "Sign the manifest file",
	Long: `
Sign the manifest file using the specified private key file and hash
algorithm extracted from the specified certificate file`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return signManifest(args)
	},
}

func signManifest(args []string) error {
	manifestFile := args[0]
	startingDir := filepath.Dir(manifestFile)
	if targetDir != "" {
		startingDir = targetDir
	}
	r, err := repo.FindRepo(startingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign Manifest: %v\n", err)
		return err
	}

	if err := r.CommitManifest(manifestFile, certFile, privFile); err != nil {
		fmt.Fprintf(os.Stderr, "Sign Manifest: cannot sign manifest %s: %v\n", manifestFile, err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.Flags().StringVarP(&privFile, "key", "k", "",
		"path of the private key file")
	signCmd.Flags().StringVarP(&certFile, "cert", "c", "",
		"path of the certificate file to get the hash algorithm from")
}

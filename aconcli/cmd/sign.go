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
	Use:     "sign manifest",
	Short:   "Sign an ACON image",
	GroupID: "image",
	Long: `
Sign the specified ACON image/manifest and store the signature in the ACON
image repo.

When signing a manifest for the first time, both a private key file and its
corresponding certificate file must be specified. The certificate file is used
to determine the hash algorithm when creating the digital signature. 'aconcli
sign' keeps symlinks (in the ACON image repo) to the private key and
certificate files to facilitate future re-signing.

When re-signing a manifest, 'aconcli sign' reuses the private key and
certifcate files by default, and can be overridden by respective command line
flags.
`,
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

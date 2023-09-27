// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"aconcli/cryptoutil"
	"github.com/spf13/cobra"
)

var hashCmd = &cobra.Command{
	Use:   "hash <certificate-file>  <manifest-file>...",
	Short: "Generate the hash digest for the manifest file",
	Long: `
Generate the hash digest for the manifest file using the hash
algorithm extracted from the specified certificate file`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doHash(args)
	},
}

func doHash(args []string) error {
	certFile := args[0]
	files := args[1:]

	certDigest, hashAlgo, err := cryptoutil.GetCertDigest(certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get hash algorithm and digest for %s: %v\n", certFile, err)
		return err
	}
	fmt.Fprintf(os.Stdout, "%s: %v\n", certFile, hex.EncodeToString(certDigest))

	for _, file := range files {
		content, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read file %s: %v\n", file, err)
			continue
		}

		content, err = canonicalJson(content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to canonicalize file %s: %v\n", file, err)
			continue
		}

		manifestDigest, err := cryptoutil.BytesDigest(content, hashAlgo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get digest for %s: %v\n", file, err)
			continue
		}
		fmt.Fprintf(os.Stdout, "%s: %v\n", file, hex.EncodeToString(manifestDigest))
	}
	return nil
}

func init() {
	rootCmd.AddCommand(hashCmd)
}

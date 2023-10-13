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
	Use:   "hash certificate [manifest]...",
	Short: "Compute SignerID and ImageIDs",
	Long: `
Compute the digests of the specified certificate and manifest files using the
hash algorithm deduced from the certificate file.

Outputs from 'aconcli hash' are the SignerID of the certificate file and the
ImageIDs of the manifest files as if signed by that certificate.
`,
	Args: cobra.MinimumNArgs(1),
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
	fmt.Fprintf(os.Stdout, "%s/%v\t%s\n", hashAlgo, hex.EncodeToString(certDigest), certFile)

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
		fmt.Fprintf(os.Stdout, "%s/%v/%v\t%s\n", hashAlgo,
			hex.EncodeToString(certDigest), hex.EncodeToString(manifestDigest), file)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(hashCmd)
}

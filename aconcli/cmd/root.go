// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "aconcli",
	Short: "A command line tool to handle Attested Containers (ACON)",
	Long: `
This tool can be used to handle various aspects of the ACON workloads.
It can generate a manifest for a workload, sign the manifest, save file
system layer contents and can also create virtual machines, run workloads
and check their status`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&targetDir, "directory", "C", "", "change to directory")
}

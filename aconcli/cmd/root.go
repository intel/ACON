// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import "github.com/spf13/cobra"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "aconcli",
	Short: "ACON (Attested Container) Command Line Interface",
	Long: `
Creates/Manages ACON (Attested Container) images and ACON virtual machines.
`,
}

func Cli() *cobra.Command {
	return rootCmd
}

func init() {
	rootCmd.AddGroup(
		&cobra.Group{"image", "ACON Image and Image Repo Commands:"},
		&cobra.Group{"runtime", "ACON TD/VM and Container Commands:"})
	rootCmd.PersistentFlags().StringVarP(&targetDir, "directory", "C", "", "change working directory before performing any operations")
}

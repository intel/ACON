// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"aconcli/config"
	"github.com/spf13/cobra"
)

var repodir string

var initCmd = &cobra.Command{
	Use:   "init [PATH_FOR_REPO]",
	Short: "Create an empty ACON repository",
	Long: `
Create an empty ACON repository under the directory if specified.
Otherwise, it will be created under current directory`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return createRepo(args)
	},
}

// Check whether we can create an ACON repository
func checkRepo(rpath string) error {
	_, err := os.Stat(rpath)
	if err == nil {
		return fs.ErrExist
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func createRepo(args []string) error {
	if targetDir != "" {
		repodir = targetDir
	} else {
		repodir = "."
	}
	repopath := filepath.Join(repodir, config.RepoDirName)

	if err := checkRepo(repopath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize ACON repository: %v\n", err)
		return err
	}

	if err := os.MkdirAll(repopath, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize ACON repository: %v\n", err)
		return err
	}

	fmt.Fprintf(os.Stdout, "Initialized empty ACON repository in %s\n", repopath)
	return nil
}

func init() {
	rootCmd.AddCommand(initCmd)
}

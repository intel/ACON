// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop <ACON virtual machine> <ACON containers>...",
	Short: "Stop ACON containers within an ACON virtual machine",
	Long: `
Stop ACON containers in an ACON virtual machine. VM can be specified by
the connection target and containers are specified by the container id.
VM and container information can be obtained by using the 'aconcli status'
subcommand`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return stopAcons(args)
	},
}

func stopAcons(args []string) error {
	conn := args[0]
	aconIds := make([]uint32, len(args[1:]))
	for i, idstr := range args[1:] {
		if id, err := strconv.ParseUint(idstr, 10, 32); err == nil {
			aconIds[i] = uint32(id)
		} else {
			fmt.Fprintf(os.Stderr, "Stop: cannot parse ACON container ID %s: %v\n", idstr, err)
			continue
		}
	}

	if err := stopAconInVM(conn, aconIds); err != nil {
		fmt.Fprintf(os.Stderr, "Stop: cannot stop ACON container: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(stopCmd)
}

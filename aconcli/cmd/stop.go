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
	Use:     "stop <ACON-virtual-machine> <ACON-containers>...",
	Short:   "Stop ACON containers",
	GroupID: "runtime",
	Long: `
Stop ACON containers in an ACON TD/VM.

The ACON TD/VM must be specified by the '-c' flag while the ACON container must
be specified by the '-e' flag. Use 'aconcli status' to list ACON TDs/VMs and
ACON containers running in them.
`,
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

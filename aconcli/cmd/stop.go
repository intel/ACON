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
	Use:   "stop ACON_VM ACON_CONTAINER ...",
	Short: "Stop ACON containers in a ACON VM",
	Long: `
Stop ACON containers in a VM. VM can be specified by the connection
method and ACON containers are specified by container ids. All the
information can be obtained by using the 'status' subcommand`,
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

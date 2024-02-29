// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strconv"

	"aconcli/service"
	"github.com/spf13/cobra"
)

var killCmd = &cobra.Command{
	Use:     "kill signo",
	Short:   "Signal an ACON container",
	GroupID: "runtime",
	Long: `
Send the specified signal to the ACON container in the specified ACON TD/VM.

The ACON TD/VM must be specified by the '-c' flag while the ACON container must
be specified by the '-e' flag. Use 'aconcli status' to list ACON TDs/VMs and
ACON containers running in them.

'signo' (signal number) could be a positive or negative integer. A positive
signo will be sent to the container process (PID 1) only, while a negative
signo will cause -signo to be sent to the whole process group led by the
container process.
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return kill(args)
	},
}

func kill(args []string) error {
	signum, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Kill: cannot get signal number from %s: %v\n", args[0], err)
		return err
	}
	c, err := service.NewAconHttpConnection(vmConnTarget, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Kill: cannot connect to %s: %v\n", vmConnTarget, err)
		return err
	}

	err = c.Kill(cid, int32(signum))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Kill: cannot call 'kill' service: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(killCmd)

	killCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"protocol/address of the ACON TD/VM")
	killCmd.MarkFlagRequired("connect")

	killCmd.Flags().Uint32VarP(&cid, "container", "e", 0,
		"the ACON container to which the signal will be sent")
	killCmd.MarkFlagRequired("container")
}

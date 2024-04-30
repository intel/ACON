// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"time"

	"aconcli/service"
	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:     "restart",
	Short:   "Restart ACON container",
	GroupID: "runtime",
	Long: `
Restart the specified ACON container in the specified ACON TD/VM.

If the specified ACON container is running, 'aconcli restart' would try to stop
it before restarting it.

The ACON TD/VM must be specified by the '-c' flag while the ACON container must
be specified by the '-e' flag. Use 'aconcli status' to list ACON TDs/VMs and
ACON containers running in them.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return restart(args)
	},
}

func restart(args []string) error {
	c, err := service.NewAconHttpConnWithOpts(vmConnTarget,
		service.OptDialTLSContextInsecure(),
		service.OptTimeout(service.DefaultServiceTimeout+time.Duration(timeout)*time.Second))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Restart: cannot connect to %s: %v\n", vmConnTarget, err)
		return err
	}

	err = c.Restart(cid, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Restart: cannot call 'restart' service: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(restartCmd)

	restartCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"connection target for the ACON virtual machine")
	restartCmd.MarkFlagRequired("connect")

	restartCmd.Flags().Uint32VarP(&cid, "container", "e", 0,
		"target ACON container to invoke the command")
	restartCmd.MarkFlagRequired("container")

	restartCmd.Flags().Uint64VarP(&timeout, "timeout", "t", 30,
		"optional timeout in seconds to wait before restarting the container")
}

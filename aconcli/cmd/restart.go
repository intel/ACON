// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"aconcli/service"
	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart specified ACON container",
	Long: `
Restart the specified ACON container within the specified virtual machine.
The ACON virtual machine needs to be specified by the '-c' flag while ACON
container needs to be specified by the '-e' flag. Both information can be
obtained by using the 'aconcli status' subcommand`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return restart(args)
	},
}

func restart(args []string) error {
	c, err := service.NewAconConnection(vmConnTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Restart: cannot connect to %s: %v\n", vmConnTarget, err)
		return err
	}
	defer c.Close()

	err = service.Restart(c, cid, timeout)
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

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
	Use:   "kill SIGNAL_NUM",
	Short: "Send a signal to an ACON container",
	Long: `
Send the specified signal to the ACON container in the VM`,
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
	c, err := service.NewAconConnection(vmConnTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Kill: cannot connect to %s: %v\n", vmConnTarget, err)
		return err
	}
	defer c.Close()

	err = service.Kill(c, cid, int32(signum))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Kill: cannot call 'kill' service: %v\n", err)
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(killCmd)

	killCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"connection target for the VM")
	killCmd.MarkFlagRequired("connect")

	killCmd.Flags().Uint32VarP(&cid, "container", "e", 0,
		"target acon container to invoke the command")
	killCmd.MarkFlagRequired("container")
}

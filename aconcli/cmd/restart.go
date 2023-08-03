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
	Use:   "restart Container_ID",
	Short: "Restart specified ACON container",
	Long: `
Restart specified ACON container in specified VM`,
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
		"connection target for the VM")
	restartCmd.MarkFlagRequired("connect")

	restartCmd.Flags().Uint32VarP(&cid, "container", "e", 0,
		"target acon container to invoke the command")
	restartCmd.MarkFlagRequired("container")

	restartCmd.Flags().Uint64VarP(&timeout, "timeout", "t", 30,
		"timeout in seconds for capturing the output")
}

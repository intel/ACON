// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"aconcli/config"
	"aconcli/service"
	"aconcli/vm"
	"github.com/spf13/cobra"
)

var force bool

var shutDownCmd = &cobra.Command{
	Use:   "shutdown <ACON-vitual-machine>...",
	Short: "Shut down ACON virtual machines and related containers",
	Long: `
Shut down ACON virtual machines and related containers. The virtual machines
need to be specified by the '-c' flag and can be obtained by using the
'aconcli status' subcommand`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return removeVM(args)
	},
}

func stopAcon(c *service.AconClient, id uint32) error {
	// try invoke 'Stop' first
	_, _, err := service.Invoke(c, id, []string{"Stop"}, 5, nil, nil, config.DefaultCapSize)
	if err == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "cannot invoke 'Stop': %v\n", err)

	// invoke 'Kill' if 'Stop' fails
	_, _, err = service.Invoke(c, id, []string{"Kill", "-HUP", "1"}, 5, nil, nil, config.DefaultCapSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot invoke 'Kill': %v\n", err)
	}

	return err
}

func stopAconInVM(conn string, ids []uint32) error {
	c, err := service.NewAconConnection(conn)
	if err != nil {
		return fmt.Errorf("cannot connect to %s: %v\n", conn, err)
	}
	defer c.Close()

	partialComplete := false
	for _, id := range ids {
		err := stopAcon(c, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot stop ACON container %v: %v\n", id, err)
			partialComplete = true
		}
	}
	if partialComplete {
		return errors.New("some ACON containers are not stopped")
	} else {
		return nil
	}
}

func removeVM(conns []string) error {
	for _, conn := range conns {
		// 'force', terminate the VM
		if force {
			pid, err := vm.GetPid(conn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Shutdown: cannot get VM pid for %s: %v\n", conn, err)
				continue
			}
			if err := vm.DestroyVM(pid); err != nil {
				fmt.Fprintf(os.Stderr, "Shutdown: cannot destroy VM %d: %v\n", pid, err)
			}
		} else {
			// non 'force', stop all the ACON containers
			states, err := getAllStatus(conn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Shutdown: cannot get ACON containers status from %s: %v\n", conn, err)
				continue
			}

			ids := make([]uint32, len(states))
			for i, s := range states {
				ids[i] = s.ContainerId
			}

			if err := stopAconInVM(conn, ids); err != nil {
				fmt.Fprintf(os.Stderr, "Shutdown: cannot stop ACON containers in %s: %v\n", conn, err)
				continue
			}
		}
	}
	return nil
}

func init() {
	rootCmd.AddCommand(shutDownCmd)
	shutDownCmd.Flags().BoolVarP(&force, "force", "f", false,
		"force terminating the virtual machines, i.e. no matter whether Shutdown/Kill command works")
}

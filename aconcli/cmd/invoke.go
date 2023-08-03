// Copyright © 2023 Intel Corporation

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"aconcli/config"
	"aconcli/service"
	"github.com/spf13/cobra"
)

var (
	sizeToCapture uint64
	inputfile     string
)

var invokeCmd = &cobra.Command{
	Use:   "invoke CUSTOM_COMMAND",
	Short: "Invoke custom command on an ACON container",
	Long: `
Invoke custom command on specified ACON container in specified ACON VM`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return invoke(args)
	},
}

func invoke(args []string) error {
	c, err := service.NewAconConnection(vmConnTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invoke: cannot connect to %s: %v\n", vmConnTarget, err)
		return err
	}
	defer c.Close()

	var data []byte
	if inputfile != "" {
		data, err = os.ReadFile(filepath.Clean(inputfile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invokd: cannot read input file %s: %v\n", inputfile, err)
			return err
		}
	}

	stdout, stderr, err := service.Invoke(c, cid, args, timeout, env, data, sizeToCapture)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invoke: cannot call 'invoke' service: %v\n", err)
		return err
	}

	if stdout != nil {
		fmt.Fprintln(os.Stdout, string(stdout))
	}
	if stderr != nil {
		fmt.Fprintln(os.Stderr, string(stderr))
	}
	return nil
}

func init() {
	rootCmd.AddCommand(invokeCmd)

	invokeCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"connection target for the VM")
	invokeCmd.MarkFlagRequired("connect")

	invokeCmd.Flags().Uint32VarP(&cid, "container", "e", 0,
		"target acon container to invoke the command")
	invokeCmd.MarkFlagRequired("container")

	invokeCmd.Flags().Uint64VarP(&timeout, "timeout", "t", 30,
		"timeout in seconds for capturing the output")

	invokeCmd.Flags().Uint64VarP(&sizeToCapture, "size", "s", config.DefaultCapSize,
		"size in bytes for capturing the output")

	invokeCmd.Flags().StringVarP(&inputfile, "input", "i", "",
		"file to get the input data")
}

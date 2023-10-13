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
	Use:     "invoke custom_command [args]...",
	Short:   "Invoke custom command in an ACON container",
	GroupID: "runtime",
	Long: `
Invoke a custom command in an existing ACON container within an ACON TD/VM.

The ACON TD/VM must be specified by the '-c' flag while the ACON container must
be specified by the '-e' flag. Use 'aconcli status' to list ACON TDs/VMs and
ACON containers running in them.

NOTE: A custom command is an executable file located in /lib/acon/entrypoint.d/
inside the ACON container's directory tree. Its file name must start with a
capital letter.
`,
	Args: cobra.MinimumNArgs(1),
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
		"protocol/address of the ACON TD/VM")
	invokeCmd.MarkFlagRequired("connect")

	invokeCmd.Flags().Uint32VarP(&cid, "container", "e", 0,
		"the ACON container to execute the custom command")
	invokeCmd.MarkFlagRequired("container")

	invokeCmd.Flags().Uint64VarP(&timeout, "timeout", "t", 30,
		"capture up to this number of seconds of the command output")

	invokeCmd.Flags().Uint64VarP(&sizeToCapture, "size", "s", config.DefaultCapSize,
		"capture up to this number of bytes of the command output")

	invokeCmd.Flags().StringVarP(&inputfile, "input", "i", "",
		"optional file serving as stdin to the command")
}

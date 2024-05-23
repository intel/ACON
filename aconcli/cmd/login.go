// Copyright © 2023 Intel Corporation

package cmd

import (
	"fmt"
	"os/user"

	"aconcli/service"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:     "login",
	Short:   "log in the ACON TD/VM",
	GroupID: "runtime",
	Long: `
Log in the specified ACON TD/VM for the current user.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return login()
	},
}

func login() error {
	c, err := service.NewAconHttpConnWithOpts(vmConnTarget, service.OptDialTLSContextInsecure())
	if err != nil {
		return fmt.Errorf("Login: cannot connect to %s: %v", vmConnTarget, err)
	}
	user, err := user.Current()
	if err != nil {
		return fmt.Errorf("Login: cannot get the current user: %v", err)
	}
	if err := c.Login(user.Uid, vmConnTarget); err != nil {
		return fmt.Errorf("Login: cannot call 'login' service: %v", err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"protocol/address of the ACON TD/VM")
	loginCmd.MarkFlagRequired("connect")
}

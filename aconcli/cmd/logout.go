// Copyright © 2023 Intel Corporation

package cmd

import (
	"fmt"
	"os/user"

	"aconcli/service"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:     "logout",
	Short:   "log out the ACON TD/VM",
	GroupID: "runtime",
	Long: `
Log out the specified ACON TD/VM for the current user. If not logged in,
this command has no effect.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return logout()
	},
}

func logout() error {
	c, err := service.NewAconHttpConnWithOpts(vmConnTarget, service.OptDialTLSContextInsecure())
	if err != nil {
		return fmt.Errorf("Logout: cannot connect to %s: %v", vmConnTarget, err)
	}
	user, err := user.Current()
	if err != nil {
		return fmt.Errorf("Logout: cannot get the current user: %v", err)
	}
	if err := c.Logout(user.Uid); err != nil {
		return fmt.Errorf("Logout: cannot call 'logout' service: %v", err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(logoutCmd)
	logoutCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"protocol/address of the ACON TD/VM")
	logoutCmd.MarkFlagRequired("connect")

}

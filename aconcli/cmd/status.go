// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aconcli/config"
	"aconcli/repo"
	"aconcli/service"
	"aconcli/vm"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show status of ACON TDs/VMs and containers",
	GroupID: "runtime",
	Long: `
Show status of all ACON TDs/VMs on the local platform and containers running in
them.
`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return showStatus()
	},
}

func getAllStatus(target string) ([]service.AconStatus, error) {
	c, err := service.NewAconHttpConnWithOpts(target, service.OptDialTLSContextInsecure())
	if err != nil {
		return nil, err
	}

	r, err := c.Inspect(0)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func printStatus(vmName string, aconStatus []service.AconStatus) {
	fmt.Printf("\nTotal %d ACON container(s) in VM %s\n", len(aconStatus), vmName)
	for i, t := range aconStatus {
		state := "Terminated"
		if t.State != 0 {
			state = string(t.State)
		}
		fmt.Printf("[%d]\tInstance ID:\t\t%d\n", i, t.ContainerId)
		fmt.Printf("\tInstance state:\t\t%s\n", state)
		fmt.Printf("\tInstance wstatus:\t%d\n", t.Wstatus)
		fmt.Printf("\tInstance bundle ID:\t%v\n", convertImageId(t.ImageId))
		fmt.Printf("\tInstance exe path:\t%v\n", t.ExePath)
		fmt.Println()
	}
}

func convertImageId(bundleId string) string {
	startingDir := "."
	if targetDir != "" {
		startingDir = targetDir
	}
	r, err := repo.FindRepo(startingDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "convert bundle id: %v\n", err)
		return bundleId
	}

	bundleIdSlice := strings.Split(bundleId, "/")
	hashAlgo := bundleIdSlice[0]
	signerDigest := bundleIdSlice[1]
	manifestDigest := bundleIdSlice[2]

	bundle, err := r.FindBundle(manifestDigest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "find bundle: %v\n", err)
		return bundleId
	}

	manifest := bundle.Manifest()
	content, err := os.ReadFile(filepath.Clean(manifest))
	if err != nil {
		return bundleId
	}

	w := repo.Workload{}
	if err := json.Unmarshal(content, &w); err != nil {
		fmt.Fprintf(os.Stderr, "cannot unmarshal %s: %v", manifest, err)
		return bundleId
	}

	productName := w.Alias.Self
	if productName == nil {
		return filepath.Join(hashAlgo, signerDigest[:config.ShortHashLen], manifestDigest[:config.ShortHashLen])
	} else {
		return productName["."][0]
	}
}

func showStatus() error {
	vmPids, conns, err := vm.GetAllVM(config.AconVmPrefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Show Status: cannot fetch VM information: %v\n", err)
		return err
	}
	fmt.Fprintf(os.Stdout, "\nTotal Runing ACON VMs: %v\n", vmPids)

	type item struct {
		conn   string
		status []service.AconStatus
		err    error
	}

	ch := make(chan item, len(conns))
	// get instaces status in each VM
	for i, conn := range conns {
		fmt.Fprintf(os.Stdout, "Inspect Virtual Machine: %s\n", vmPids[i])
		go func(c string) {
			var it item
			it.conn = c
			it.status, it.err = getAllStatus(c)
			ch <- it
		}(conn)
	}

	for range conns {
		it := <-ch
		if it.err != nil {
			fmt.Fprintf(os.Stderr, "Show Status: cannot fetch status from %s: %v\n", it.conn, it.err)
			continue
		}
		printStatus(it.conn, it.status)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

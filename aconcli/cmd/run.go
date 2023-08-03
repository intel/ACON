// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"aconcli/repo"
	"aconcli/service"
	"aconcli/vm"
	"github.com/spf13/cobra"
)

var (
	loadRepo     bool
	autoload     bool
	loadonly     []string
	debug        bool
	startnew     bool
	timetolive   int
	startfile    string
	vmConnTarget string
)

var runCmd = &cobra.Command{
	Use:   "run [MANIFEST_FILE]...",
	Short: "Start ACON containers",
	Long: `
Start ACON container(s) in a new or existing ACON VM using ACON images.

ACON images can be specified on the command line either as a list of manifests
or using flag '-a', which means all the images in the ACON repository.

The script file to launch the VM can be specified by the user. If not specified,
the default one from aconcli installation will be used. initrd and kernel image
can be separately specified using environment variables ACON_STARTVM_PARAM_RAMDISK
and ACON_STARTVM_PARAM_KERNEL respectively. If not specified, default images from
aconcli installation will be used.

ACON container can be run in the foreground or background.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(args)
	},
}

func loadBundle(client *service.AconClient, r *repo.Repo, b *repo.Bundle, needStart bool, env []string) error {
	aconJSON, err := os.ReadFile(b.Manifest())
	if err != nil {
		return err
	}

	aconJSON, err = canonicalJson(aconJSON)
	if err != nil {
		return err
	}

	sig, err := os.ReadFile(b.Sig())
	if err != nil {
		return err
	}

	cert, err := os.ReadFile(b.Cert())
	if err != nil {
		return err
	}

	// AddManifest
	bundleId, layers, err := service.AddManifest(client, string(aconJSON), sig, cert)
	if err != nil {
		return fmt.Errorf("AddManifest: %v", err)
	}
	log.Printf("Received ACON Manifest, ID: %s", bundleId)
	if len(layers) > 0 {
		log.Println("Missing layers:")
		for i, layer := range layers {
			log.Printf("\t[%v]: %q\n", i, layer)
		}
	}

	for _, layer := range layers {
		if !strings.HasPrefix(layer, "sha") {
			return fmt.Errorf("loadBundle: unresolved layer %v", layer)
		}
	}

	for _, layer := range layers {
		data, err := r.BlobData(layer)
		if err != nil {
			log.Fatalf("cannot get blob data for %s: %v", layer, err)
		}

		err = service.AddBlob(client, 2, data)
		if err != nil {
			log.Fatalf("Failed, AddBlob %s: %v", layer, err)
		} else {
			log.Printf("Added File System Layer: %s\n", layer)
		}
	}

	if needStart {
		aconId, err := service.Start(client, bundleId, env)
		if err != nil {
			return fmt.Errorf("loadBundle: fail to start bundle: %v", err)
		}
		log.Printf("Started ACON Instance, ID: %v", aconId)
	}
	return nil
}

func equalBundleList(x, y []*repo.Bundle) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func loadAll(c *service.AconClient, r *repo.Repo,
	bundles []*repo.Bundle, needstart bool, env []string) error {
	num := len(bundles)
	if num == 0 {
		return nil
	} else if num == 1 {
		return loadBundle(c, r, bundles[0], needstart, env)
	}

	var nextRound []*repo.Bundle
	for _, b := range bundles {
		if err := loadBundle(c, r, b, needstart, env); err != nil {
			nextRound = append(nextRound, b)
		}
	}
	// no more progress
	if equalBundleList(bundles, nextRound) {
		return fmt.Errorf("loadAll: fail to load %v", nextRound)
	}

	return loadAll(c, r, nextRound, needstart, env)
}

// caller needs to close the connection
func connect(conn string) (*service.AconClient, error) {
	return service.NewAconConnection(conn)
}

func prepareEnvVsock() []string {
	return []string{
		"ACON_STARTVM_PARAM_VSOCK_CONN=acond.vsock_conn"}
}

func prepareEnvTcp(connTarget string) []string {
	return []string{
		fmt.Sprintf("ACON_STARTVM_PARAM_TCPFWD=%v:1025", connTarget)}
}

func run(args []string) error {
	var cmd *exec.Cmd
	var manifests []string
	var startVMOnly bool

	specificManifest := len(args) > 0

	if specificManifest && loadRepo {
		fmt.Fprintf(os.Stderr, "Specifying manifests and loading all manifests"+
			"in the repository at the same time is not allowed\n")
		return errors.New("Invalid operation")
	}

	if specificManifest {
		manifests = args
	} else if !loadRepo {
		startVMOnly = true
	}

	if startnew {
		env := os.Environ()
		if !strings.HasPrefix(vmConnTarget, ":") {
			cid := os.Getenv("CID")
			vsock_env := prepareEnvVsock()
			env = append(env, vsock_env...)
			vmConnTarget = fmt.Sprintf("vsock://%v:%v", cid, vmConnTarget)
		} else {
			tcp_env := prepareEnvTcp(string(vmConnTarget[1:]))
			env = append(env, tcp_env...)
			vmConnTarget = fmt.Sprintf("tcp://%v", vmConnTarget)
		}
		env = append(env,
			fmt.Sprintf("ACON_STARTVM_PARAM_CONN_TARGET=%v", vmConnTarget))

		var err error
		cmd, err = vm.StartVM(startfile, debug, env)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Run: cannot start virtual machine, start script (%s): %v\n", startfile, err)
			return err
		}
		log.Printf("Created Virtual Machine, PID: %d, Connection: %v\n", cmd.Process.Pid, vmConnTarget)
	}

	if !startVMOnly {
		startingDir := "."
		if len(manifests) > 0 {
			startingDir = filepath.Dir(manifests[0])
		}
		if targetDir != "" {
			startingDir = targetDir
		}
		r, err := repo.FindRepo(startingDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Run: %v\n", err)
			return err
		}

		c, err := connect(vmConnTarget)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Run: cannot connect to %s: %v\n", vmConnTarget, err)
			return err
		}
		defer c.Close()

		var bundles []*repo.Bundle
		if len(manifests) > 0 {
			// specific manifests
			bundles, err = r.BundleChain(manifests[0])
		} else if loadRepo {
			// whole repo
			bundles, err = r.AllBundles()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Run: cannot get workloads: %v\n", err)
			return err
		}
		if err := loadAll(c, r, bundles, true, env); err != nil {
			fmt.Fprintf(os.Stderr, "Run: cannot run workloads: %v\n", err)
			return err
		}
	}
	if startnew && debug {
		cmd.Wait()
	}
	return nil
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().BoolVarP(&startnew, "new", "n", false,
		"start the container in a new ACON VM")

	runCmd.Flags().BoolVarP(&debug, "interactive", "i", false,
		"bring VM to the foreground for debugging")

	runCmd.Flags().BoolVarP(&loadRepo, "Auto", "A", false,
		"load/start all the workloads in the ACON repository")

	runCmd.Flags().BoolVarP(&autoload, "auto", "a", false,
		"automatically load depending manifests")

	runCmd.Flags().StringSliceVarP(&loadonly, "loadonly", "l", nil,
		"manifests to be loaded only")

	runCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"start the container in an existing VM specified by the connect target")

	runCmd.Flags().IntVarP(&timetolive, "timetolive", "t", 60,
		"timeout for the newly created VM to exist")

	runCmd.Flags().StringVarP(&startfile, "file", "f", "",
		"path of the file to start the VM")

	runCmd.Flags().StringSliceVar(&env, "env", nil,
		"environment variables to be used")
}

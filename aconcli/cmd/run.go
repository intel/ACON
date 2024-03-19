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
	"strconv"
	"strings"

	"aconcli/config"
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
	finalize     bool
)

var runCmd = &cobra.Command{
	Use:     "run [manifest]...",
	Short:   "Start ACON containers",
	GroupID: "runtime",
	Long: `
Start ACON container(s) in a new or existing ACON TD/VM.

ACON images (identified by their manifests) can be listed explicitly on the
command line, in which case all specified images will be started.

Alternatively, the flag '-A' can be supplied to simply start all executable
ACON images in the current repo.

'aconcli run' invokes an external executable whenever it needs to launch a new
ACON TD/VM. The flag '-f' can be used to specified the path to that executbale,
or if omitted, the default is 'acon-startvm' in the same directory as where
'aconcli' resides.

'aconcli run' passes arguments to 'acon-startvm' (or its substitute specified
by '-f') via environment variables, listed below. More details are available in
comments inside the default 'acon-startvm' script file

- ATD_TCPFWD - TCP forwarding rules.

ACON containers may run in the foreground (the flag '-i') to facilitate
debugging.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(args)
	},
}

func loadBundle(client service.AconClient, r *repo.Repo, b *repo.Bundle, needStart bool, env []string) error {
	// AddManifest
	bundleId, layers, err := client.AddManifest(b.Manifest(), b.Sig(), b.Cert())
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
		blobpath := r.BlobPath(layer)
		err = client.AddBlob(2, blobpath)
		if err != nil {
			log.Fatalf("Failed, AddBlob %s: %v", layer, err)
		} else {
			log.Printf("Added File System Layer: %s\n", layer)
		}
	}

	if finalize {
		err = client.Finalize()
		if err != nil {
			log.Fatalf("Failed, Finalize: %v", err)
		} else {
			log.Printf("Finalized to load images\n")
		}
	}

	if needStart {
		aconId, err := client.Start(bundleId, env)
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

func loadAll(c service.AconClient, r *repo.Repo,
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
func connect(conn string) (*service.AconClientHttp, error) {
	return service.NewAconHttpConnection(conn, true)
}

func prepareEnvVsock() string {
	cid := os.Getenv("ATD_CID")
	if cid == "" {
		cid = strconv.Itoa(os.Getpid())
		os.Setenv("ATD_CID", cid)
	}
	os.Setenv("ATD_KPARAMS", strings.TrimSpace(os.Getenv("ATD_KPARAMS")+" acond.vsock_conn"))
	return cid
}

func prepareEnvTcp(connTarget string) {
	os.Setenv("ATD_TCPFWD", strings.Trim(fmt.Sprintf("%v:1025,%v", connTarget, os.Getenv("ATD_TCPFWD")), ", "))
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
		if !strings.HasPrefix(vmConnTarget, ":") {
			vmConnTarget = fmt.Sprintf("vsock://%v:%v", prepareEnvVsock(), vmConnTarget)
		} else {
			prepareEnvTcp(string(vmConnTarget[1:]))
		}

		var err error
		cmd, err = vm.StartVM(startfile, debug, append(os.Environ(), config.AconVmEnvTag+vmConnTarget))
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
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to determine path to aconcli executable: %v", err)
	}

	rootCmd.AddCommand(runCmd)

	runCmd.Flags().BoolVarP(&startnew, "new", "n", false,
		"start a new ACON TD/VM")

	runCmd.Flags().BoolVarP(&debug, "interactive", "i", false,
		"run ACON TD/VM in foreground (usually for debugging)")

	runCmd.Flags().BoolVarP(&loadRepo, "all", "A", false,
		"load/start all images in the current ACON image repo")

	runCmd.Flags().BoolVarP(&autoload, "auto", "a", false,
		"load dependencies automatically")

	runCmd.Flags().StringSliceVarP(&loadonly, "loadonly", "l", nil,
		"load (but do not start) the specified images")

	runCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"connect target url")

	runCmd.Flags().IntVarP(&timetolive, "timetolive", "t", 60,
		"shut down the TD/VM after being idle for specified number of seconds")

	runCmd.Flags().StringVarP(&startfile, "file", "f", filepath.Join(filepath.Dir(exe), "acon-startvm"),
		"path to the executable for launching ACON TD/VM")

	runCmd.Flags().StringSliceVar(&env, "env", nil,
		"set environment variables inside new containers")

	runCmd.Flags().BoolVar(&finalize, "finalize", true,
		"finalize the process of loading images to ACON TD/VM")
}

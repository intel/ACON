// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package vm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"aconcli/config"

	"github.com/prometheus/procfs"
)

const (
	procDir       = "/proc"
	commfile      = "comm"
	aconStartFile = "acon-startvm"
)

func exePath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find aconcli executable failed: %v", err)
	}
	// If a symlink was used to start the process, depending on the operating system,
	// the result might be the symlink or the path it pointed to. If a stable result
	// is needed, path/filepath.EvalSymlinks might help.
	return filepath.EvalSymlinks(ex)
}

func getQemuStartFile(startfile string) (string, error) {
	if len(startfile) > 0 {
		return startfile, nil
	}
	exepath, err := exePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exepath), aconStartFile), nil
}

func StartVM(startfile string, foreground bool, env []string) (*exec.Cmd, error) {
	qemuStartFile, err := getQemuStartFile(startfile)
	if err != nil {
		return nil, fmt.Errorf("startVM failed: %v", err)
	}

	cmd := exec.Cmd{Path: qemuStartFile, Env: env}

	if foreground {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Foreground: true,
		}
	}
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("startVM failed: %v", err)
	}
	time.Sleep(time.Second)
	return &cmd, nil
}

func DestroyVM(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGTERM)
}

func GetAllVM(vmNamePrefix string) ([]string, []string, error) {
	matches, err := filepath.Glob(procDir + "/[0-9]*[0-9]")
	if err != nil {
		return nil, nil, fmt.Errorf("get all vm: cannot glob pid directory: %v", err)
	}

	var pids []string
	var conns []string
	for _, match := range matches {
		finfo, err := os.Stat(match)
		if err != nil || !finfo.IsDir() {
			continue
		}
		comm, err := evalCommFile(filepath.Join(match, commfile))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if !strings.HasPrefix(comm, vmNamePrefix) {
			continue
		}
		pid := filepath.Base(match)
		if conn, err := getConnTarget(pid); err == nil {
			pids = append(pids, pid)
			conns = append(conns, conn)
		}
	}
	return pids, conns, nil
}

func GetPid(connTarget string) (int, error) {
	vmPids, conns, err := GetAllVM(config.AconVmPrefix)
	if err != nil {
		return -1, fmt.Errorf("get pid for (%s): %v", connTarget, err)
	}

	for i, conn := range conns {
		if conn == connTarget {
			return strconv.Atoi(vmPids[i])
		}
	}
	return -1, fmt.Errorf("get pid for (%s): cannot get matching pid", connTarget)
}

func evalCommFile(f string) (string, error) {
	c, err := os.ReadFile(filepath.Clean(f))
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(string(c))
	return name, nil
}

func getConnTarget(pid string) (string, error) {
	targetPid, err := strconv.Atoi(pid)
	if err != nil {
		return "", fmt.Errorf("cannot convert pid for %s", pid)
	}
	pfs, err := procfs.NewDefaultFS()
	if err != nil {
		return "", fmt.Errorf("cannot new default FS, err %v", err)
	}

	p, err := pfs.Proc(targetPid)
	if err != nil {
		return "", fmt.Errorf("cannot Proc: %v", err)
	}

	environ, err := p.Environ()
	if err != nil {
		return "", fmt.Errorf("cannot get env var for pid %s: %v", pid, err)
	}

	var connTarget string
	for _, ev := range environ {
		if strings.HasPrefix(ev, config.AconVmEnvTag) {
			connTarget = ev
			break
		}
	}

	if connTarget == "" {
		return "", fmt.Errorf("cannot find vm connection target")
	}

	_, v, found := strings.Cut(connTarget, "=")
	if !found {
		return "", fmt.Errorf("getConnTarget: malformed tdvm connection ENV VAR %v", connTarget)
	}

	return v, nil
}

// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"aconcli/cmd"
	"os"
)

func main() {
	if err := cmd.Cli().Execute(); err != nil {
		os.Exit(1)
	}
}

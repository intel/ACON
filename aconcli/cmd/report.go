// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"aconcli/attest"
	"aconcli/service"
	"github.com/spf13/cobra"
)

var (
	isQuote bool
	file    string
)

func printReportType(reportType *attest.ReportType) {
	if reportType.Type == 0 {
		fmt.Fprintf(os.Stdout, "TEE Type: SGX\n")
	} else if reportType.Type == 0x81 {
		fmt.Fprintf(os.Stdout, "TEE Type: TDX\n")
	}
	fmt.Fprintf(os.Stdout, "Subtype: %v\n", reportType.Subtype)
	fmt.Fprintf(os.Stdout, "Version: %v\n", reportType.Version)
}

func printReportMac(reportMac *attest.ReportMac) {
	fmt.Fprintf(os.Stdout, "--- Report Mac Struct ---\n")
	printReportType(&reportMac.ReportType)
	fmt.Fprintf(os.Stdout, "CPU SVN: 0x%v\n", hex.EncodeToString(reportMac.CpuSvn[:]))
	fmt.Fprintf(os.Stdout, "TEE TCB Info Hash: 0x%v\n", reportMac.TeeTcbInfoHash)
	fmt.Fprintf(os.Stdout, "TEE Info Hash: 0x%v\n", reportMac.TeeInfoHash)
	fmt.Fprintf(os.Stdout, "Report Data: 0x%v\n", reportMac.ReportData)
	fmt.Fprintf(os.Stdout, "MAC: 0x%v\n", hex.EncodeToString(reportMac.Mac[:]))
}

func printTeeTcbInfo(teeTcbInfo *attest.TeeTcbInfo) {
	fmt.Fprintf(os.Stdout, "--- TEE TCB Info ---\n")
	fmt.Fprintf(os.Stdout, "0x%v\n", hex.EncodeToString(teeTcbInfo.Data[:]))
}

func printTdInfo(tdInfo *attest.TdInfo) {
	fmt.Fprintf(os.Stdout, "--- TD Info Struct ---\n")
	fmt.Fprintf(os.Stdout, "Attributes: %v\n", tdInfo.Attributes)
	fmt.Fprintf(os.Stdout, "XFAM: %v\n", tdInfo.Xfam)
	fmt.Fprintf(os.Stdout, "MRTD: %v\n", tdInfo.Mrtd)
	fmt.Fprintf(os.Stdout, "MR Config ID: %v\n", tdInfo.MrConfigId)
	fmt.Fprintf(os.Stdout, "MR Owner: %v\n", tdInfo.MrOwner)
	fmt.Fprintf(os.Stdout, "MR Owner Config: %v\n", tdInfo.MrOwnerConfig)
	fmt.Fprintf(os.Stdout, "RTMR:\n")
	for i := range [attest.NUM_RTMRS]int{} {
		fmt.Fprintf(os.Stdout, "%d: %v\n", i, tdInfo.Rtmr[i])
	}
	fmt.Fprintf(os.Stdout, "Service TD Hash: %v\n", tdInfo.ServTdHash)
}

func parseReport(report []byte) error {
	if len(report) != 1024 {
		return errors.New("report data length error")
	}

	reportStruct := attest.TdReport{}
	err := binary.Read(bytes.NewReader(report), binary.LittleEndian, &reportStruct)
	if err != nil {
		return fmt.Errorf("parse report: %v\n", err)
	}
	printReportMac(&reportStruct.ReportMac)
	printTeeTcbInfo(&reportStruct.TeeTcbInfo)
	printTdInfo(&reportStruct.TdInfo)
	return nil
}

var reportCmd = &cobra.Command{
	Use:     "report [nonce-low]  [nonce-high]",
	Short:   "Request TD report or Quote",
	GroupID: "runtime",
	Long: `
Request a TD report or Quote from an ACON TD/VM.

The ACON TD/VM must be specified by the '-c' flag. Use 'aconcli status' to list
ACON TDs/VMs and ACON containers running in them.
`,
	Args: cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		return getReport(args)
	},
}

func getReport(args []string) error {
	c, err := service.NewAconConnection(vmConnTarget)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Report: cannot connect to %s: %v\n", vmConnTarget, err)
		return err
	}
	defer c.Close()

	var nl uint64
	var nh uint64
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)

	if len(args) == 0 {
		nl = r.Uint64()
		nh = r.Uint64()
	}
	if len(args) == 1 {
		nl, err = strconv.ParseUint(args[0], 0, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Report: cannot convert nonce low %s: %v\n", args[0], err)
			return err
		}
		nh = r.Uint64()
	}
	if len(args) == 2 {
		nl, err = strconv.ParseUint(args[0], 0, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Report: cannot convert nonce low %s: %v\n", args[0], err)
			return err
		}
		nh, err = strconv.ParseUint(args[1], 0, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Report: cannot convert nonce high %s: %v\n", args[1], err)
			return err
		}
	}

	var requestType uint32
	if isQuote {
		requestType = 1
	} else {
		requestType = 0
	}
	data, _, _, _, mrlog3, attest_data, err := service.Report(c, nl, nh, requestType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Report: cannot call 'report' service: %v\n", err)
		return err
	}
	fmt.Fprintf(os.Stdout, "mrlog3:\n%v\n", mrlog3)
	fmt.Fprintf(os.Stdout, "attestation data:\n%v\n", attest_data)

	if err := os.WriteFile(file, data, 0600); err != nil {
		return err
	}

	if isQuote {
		return nil
	} else {
		return parseReport(data)
	}
}

func init() {
	rootCmd.AddCommand(reportCmd)

	reportCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"connection target for the ACON virtual machine")
	reportCmd.MarkFlagRequired("conn")
	reportCmd.Flags().BoolVarP(&isQuote, "quote", "q", false,
		"getting quote instead of getting report")
	reportCmd.Flags().StringVarP(&file, "file", "f", "",
		"file path to dump the report or quote raw data")
}

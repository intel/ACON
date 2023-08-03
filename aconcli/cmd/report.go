// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"

	"aconcli/service"
	"github.com/spf13/cobra"
)

const NUM_RTMRS = 4

type TdReport struct {
	ReportMac
	TeeTcbInfo
	Reserved [17]byte
	TdInfo
}

type ReportType struct {
	Type     byte
	Subtype  byte
	Version  byte
	Reserved byte
}

type ReportMac struct {
	ReportType
	Reserved0      [12]byte
	CpuSvn         [16]byte
	TeeTcbInfoHash [48]byte
	TeeInfoHash    [48]byte
	ReportData     [64]byte
	Reserved1      [32]byte
	Mac            [32]byte
}

type TeeTcbInfo struct {
	Data [239]byte
}

type TdInfo struct {
	Attributes    [8]byte             // TD's attributes
	Xfam          [8]byte             // TD's XFAM
	Mrtd          [48]byte            // Measurement of initial contents of the TD
	MrConfigId    [48]byte            // Software-defined ID for non-owner-defined configuration of the guest TD
	MrOwner       [48]byte            // Software-defined ID for the guest TD's owner
	MrOwnerConfig [48]byte            // Software-defined ID for owner-defined configuration of the guest TD
	Rtmr          [NUM_RTMRS][48]byte // Array of NUM_RTMRS(4) run-time extendable measurement registers
	ServTdHash    [48]byte
	Reserved      [64]byte
}

func printReportType(reportType *ReportType) {
	if reportType.Type == 0 {
		fmt.Fprintf(os.Stdout, "TEE Type: SGX\n")
	} else if reportType.Type == 0x81 {
		fmt.Fprintf(os.Stdout, "TEE Type: TDX\n")
	}
	fmt.Fprintf(os.Stdout, "Subtype: %v\n", reportType.Subtype)
	fmt.Fprintf(os.Stdout, "Version: %v\n", reportType.Version)
}

func printReportMac(reportMac *ReportMac) {
	fmt.Fprintf(os.Stdout, "--- Report Mac Struct ---\n")
	printReportType(&reportMac.ReportType)
	fmt.Fprintf(os.Stdout, "CPU SVN: 0x%v\n", hex.EncodeToString(reportMac.CpuSvn[:]))
	fmt.Fprintf(os.Stdout, "TEE TCB Info Hash: 0x%v\n", hex.EncodeToString(reportMac.TeeTcbInfoHash[:]))
	fmt.Fprintf(os.Stdout, "TEE Info Hash: 0x%v\n", hex.EncodeToString(reportMac.TeeInfoHash[:]))
	fmt.Fprintf(os.Stdout, "Report Data: 0x%v\n", hex.EncodeToString(reportMac.ReportData[:]))
	fmt.Fprintf(os.Stdout, "MAC: 0x%v\n", hex.EncodeToString(reportMac.Mac[:]))
}

func printTeeTcbInfo(teeTcbInfo *TeeTcbInfo) {
	fmt.Fprintf(os.Stdout, "--- TEE TCB Info ---\n")
	fmt.Fprintf(os.Stdout, "0x%v\n", hex.EncodeToString(teeTcbInfo.Data[:]))
}

func printTdInfo(tdInfo *TdInfo) {
	fmt.Fprintf(os.Stdout, "--- TD Info Struct ---\n")
	fmt.Fprintf(os.Stdout, "Attributes: 0x%v\n", hex.EncodeToString(tdInfo.Attributes[:]))
	fmt.Fprintf(os.Stdout, "XFAM: 0x%v\n", hex.EncodeToString(tdInfo.Xfam[:]))
	fmt.Fprintf(os.Stdout, "MRTD: 0x%v\n", hex.EncodeToString(tdInfo.Mrtd[:]))
	fmt.Fprintf(os.Stdout, "MR Config ID: 0x%v\n", hex.EncodeToString(tdInfo.MrConfigId[:]))
	fmt.Fprintf(os.Stdout, "MR Owner: 0x%v\n", hex.EncodeToString(tdInfo.MrOwner[:]))
	fmt.Fprintf(os.Stdout, "MR Owner Config: 0x%v\n", hex.EncodeToString(tdInfo.MrOwnerConfig[:]))
	fmt.Fprintf(os.Stdout, "RTMR:\n")
	for i := range [NUM_RTMRS]int{} {
		fmt.Fprintf(os.Stdout, "%d: 0x%v\n", i, hex.EncodeToString(tdInfo.Rtmr[i][:]))
	}
	fmt.Fprintf(os.Stdout, "Service TD Hash: 0x%v\n", hex.EncodeToString(tdInfo.ServTdHash[:]))
}

func parseReport(report []byte) error {
	if len(report) != 1024 {
		return errors.New("report data length error")
	}

	reportStruct := TdReport{}
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
	Use:   "report NONCE_LOW NONCE_HIGH",
	Short: "Get TD report from specified ACON container",
	Long: `
Get the TD Report from specified ACON container, given
the 64-bit hexadecimal low and high nonce values`,
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

	nl, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Report: cannot convert %s: %v\n", args[0], err)
		return err
	}

	nh, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Report: cannot convert %s: %v\n", args[1], err)
		return err
	}

	report, mrlog0, mrlog1, mrlog2, mrlog3, attest_data, err := service.Report(c, nl, nh)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Report: cannot call 'report' service: %v\n", err)
		return err
	}

	fmt.Fprintf(os.Stdout, "mrlog0:\n%v\n", mrlog0)
	fmt.Fprintf(os.Stdout, "mrlog1:\n%v\n", mrlog1)
	fmt.Fprintf(os.Stdout, "mrlog2:\n%v\n", mrlog2)
	fmt.Fprintf(os.Stdout, "mrlog3:\n%v\n", mrlog3)
	fmt.Fprintf(os.Stdout, "attestation data:\n%v\n", attest_data)

	fmt.Fprintf(os.Stdout, "raw report:\n%v\n", report)
	return parseReport(report)
}

func init() {
	rootCmd.AddCommand(reportCmd)

	reportCmd.Flags().StringVarP(&vmConnTarget, "connect", "c", "",
		"connection target for the VM")
	reportCmd.MarkFlagRequired("conn")
}

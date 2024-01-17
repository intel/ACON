// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"aconcli/attest"
)

const (
	RtmrLog0 uint = iota
	RtmrLog1
	RtmrLog2
	RtmrLog3
)

const (
	FinalizedLogEntry = "github.com/intel/ACON Finalize"
	Green             = "\033[1;32m%s\033[0m"
	Red               = "\033[1;31m%s\033[0m"
)

type QuoteHeader struct {
	RtmrLogOffset uint32
	AttestOffset  uint32
	DataOffset    uint32
}

var (
	Success = Colorwrapper(Green)
	Fail    = Colorwrapper(Red)
)

func Colorwrapper(c string) func(...interface{}) string {
	colorize := func(args ...interface{}) string {
		return fmt.Sprintf(c, fmt.Sprint(args...))
	}
	return colorize
}

func dumpAttestInfo(a *attest.AttestData) {
	//fmt.Fprintf(os.Stdout, "api version: %v\n", a.ApiVersion)
	//fmt.Fprintf(os.Stdout, "requestor nonce: %v\n", a.RequestorNonce)
	//fmt.Fprintf(os.Stdout, "acond nonce: %v\n", a.AcondNonce)
	for imageId, cInfo := range a.AttestationData {
		fmt.Fprintf(os.Stdout, "ACON image ID: %v\n", imageId[:18])
		for i, v := range cInfo {
			fmt.Fprintf(os.Stdout, "\tcontainer ID: %v\n", i)
			fmt.Fprintf(os.Stdout, "\tattestation data: %v\n", v.Data)
		}
	}
}

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("connect error:", err)
		return
	}
	defer conn.Close()

	// get data from sample server
	var data []byte
	buf := make([]byte, 1024)
	length := 0
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, Fail("Fail: Reading quote data from server\n"))
				return
			}
			break
		}
		data = append(data, buf[:n]...)
		length += n
	}

	// parse quote, log and attestation data
	header := new(QuoteHeader)
	err = binary.Read(bytes.NewReader(data), binary.LittleEndian, header)
	if err != nil {
		fmt.Fprintf(os.Stderr, Fail("Fail: Parsing TD Quoting data, not in a TD environment?\n"))
		return
	}

	fmt.Fprintf(os.Stdout, Success("Success: Getting TD quoting data\n"))

	rtmrLog := data[header.RtmrLogOffset:header.AttestOffset]
	attestData := data[header.AttestOffset:header.DataOffset]
	quote := data[header.DataOffset:]

	quoteStruct, err := attest.ParseQuote(quote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse quote error: %v\n", err)
		return
	}
	q, err := json.MarshalIndent(quoteStruct, "", "    ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal quote to json error: %v\n", err)
		return
	}

	if err := os.WriteFile("quote.json", q, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write out quote json file error: %v\n", err)
		return
	}

	if err := attest.WriteQuote("quote.bin", quote); err != nil {
		fmt.Fprintf(os.Stderr, "write out quote binary data error: %v\n", err)
		return
	}

	// verify quote using existing application from DCAP quote verify library
	verifierPath := filepath.Dir(os.Args[0]) + "/app"
	ok, err := attest.VerifyQuote(verifierPath, "./quote.bin")
	if !ok {
		fmt.Fprintf(os.Stderr, Fail("Fail: Verify quote\n"))
		return
	} else {
		fmt.Fprintf(os.Stdout, Success("Success: Verifying quote\n"))
	}

	logs := strings.Split(string(rtmrLog[RtmrLog3:]), "\x00")
	logs = logs[:len(logs)-1]
	// check whether there exists a 'Finalized' log entry
	finalizedlogFound := false
	for _, e := range logs {
		if e == FinalizedLogEntry {
			finalizedlogFound = true
			break
		}
	}
	if !finalizedlogFound {
		fmt.Fprintf(os.Stderr, Fail("Fail: Security check - The RTMR logs are not finalized\n"))
		return
	}

	fmt.Fprintf(os.Stdout, Success("Success: Security check - The RTMR logs are finalized\n"))

	// dislay attestation related information
	a, err := attest.ParseAttestData(attestData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse attest data error: %v\n", err)
		return
	}
	dumpAttestInfo(a)

	// check whether evaluated rtmr value and rtmr value from quote match
	mr := hex.EncodeToString(attest.GetRtmrValue(logs))
	r3 := quoteStruct.ReportBody.Rtmr[RtmrLog3]
	mrFromQuote := hex.EncodeToString(r3.M[:])
	if mr != mrFromQuote {
		fmt.Fprintf(os.Stderr, Fail("Fail: Security check - Evaluated RTMR value and RTMR value from quote do not match\n"))
		//fmt.Fprintf(os.Stderr, "Evaluated: %v\n", mr)
		//fmt.Fprintf(os.Stderr, "From quote: %v\n", mrFromQuote)
		return
	} else {
		fmt.Fprintf(os.Stderr, Success("Success: Security check - Evaluated RTMR value and RTMR value from quote match\n"))
		//fmt.Fprintf(os.Stderr, "RTMR value: %v\n", mr)
		return
	}
}

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
	"strings"

	"aconcli/attest"
)

const (
	RtmrLog0 uint = iota
	RtmrLog1
	RtmrLog2
	RtmrLog3
)

type QuoteHeader struct {
	RtmrLogOffset uint32
	AttestOffset  uint32
	DataOffset    uint32
}

func dumpAttestInfo(a *attest.AttestData) {
	fmt.Fprintf(os.Stdout, "api version: %v\n", a.ApiVersion)
	fmt.Fprintf(os.Stdout, "requestor nonce: %v\n", a.RequestorNonce)
	fmt.Fprintf(os.Stdout, "acond nonce: %v\n", a.AcondNonce)
	for imageId, cInfo := range a.AttestationData {
		fmt.Fprintf(os.Stdout, "ACON image ID: %v\n", imageId)
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
				fmt.Fprintf(os.Stderr, "read quote error: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "parse quote header error: %v\n", err)
		return
	}

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

	if err := attest.WriteQuote(quote); err != nil {
		fmt.Fprintf(os.Stderr, "write out quote binary data error: %v\n", err)
		return
	}

	// verify quote using existing application from DCAP quote verify library
	ok, err := attest.VerifyQuote("./quote.bin")
	if !ok {
		fmt.Fprintf(os.Stderr, "verify quote failed, error: %v\n", err)
		return
	} else {
		fmt.Fprintf(os.Stdout, "verify quote successfully\n")
	}

	// dislay attestation related information
	a, err := attest.ParseAttestData(attestData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse attest data error: %v\n", err)
		return
	}
	dumpAttestInfo(a)

	// check whether evaluated rtmr value and rtmr value from quote match
	logs := strings.Split(string(rtmrLog[RtmrLog3:]), "\x00")
	logs = logs[:len(logs)-1]
	mr := hex.EncodeToString(attest.GetRtmrValue(logs))
	r3 := quoteStruct.ReportBody.Rtmr[RtmrLog3]
	mrFromQuote := hex.EncodeToString(r3.M[:])
	if mr != mrFromQuote {
		fmt.Fprintf(os.Stderr, "Evaluated RTMR value and RTMR value from quote do not match\n")
		fmt.Fprintf(os.Stderr, "Evaluated: %v\n", mr)
		fmt.Fprintf(os.Stderr, "From quote: %v\n", mrFromQuote)
		return
	} else {
		fmt.Fprintf(os.Stderr, "Evaluated RTMR value and RTMR value from quote match\n")
		fmt.Fprintf(os.Stderr, "RTMR value: %v\n", mr)
		return
	}
}

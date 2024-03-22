// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	Green             = "\033[0;32m"
	Red               = "\033[0;31m"
	Bold              = "\033[1m"
	NoColor           = "\033[0m"
)

type QuoteHeader struct {
	RtmrLogOffset uint32
	AttestOffset  uint32
	DataOffset    uint32
}

func Doing(what string) {
	fmt.Printf("    %-60s", what+"...")
	time.Sleep(200 * time.Millisecond)
}

func Ok() {
	fmt.Println(Green + "Ok" + NoColor)
}

func Failed() {
	fmt.Println(Red + "Failed" + NoColor)
}

func Passed() {
	fmt.Println(Green + "Passed" + NoColor)
}

func dumpAttestInfo(a *attest.AttestData) {
	//fmt.Fprintf(os.Stdout, "api version: %v\n", a.ApiVersion)
	//fmt.Fprintf(os.Stdout, "requestor nonce: %v\n", a.RequestorNonce)
	//fmt.Fprintf(os.Stdout, "acond nonce: %v\n", a.AcondNonce)
	for imageId, cInfo := range a.AttestationData {
		fmt.Printf(Bold+"\tIMAGE"+NoColor+" -- %v\n", imageId[:18])
		for i, v := range cInfo {
			fmt.Printf(Bold+"\t    ContainerID"+NoColor+"\t%v\n", i)
			fmt.Printf(Bold+"\t    Data"+NoColor+"\t%v\n", v.Data)
		}
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %v PORT\n", os.Args[0])
		return
	}

	conn, err := net.Dial("tcp", "localhost:"+os.Args[1])
	if err != nil {
		fmt.Println("connect error:", err)
		return
	}
	defer conn.Close()

	// get data from sample server
	Doing("Requesting quote from server")

	var data []byte
	buf := make([]byte, 1024)
	length := 0
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				Failed()
				return
			}
			break
		}
		data = append(data, buf[:n]...)
		length += n
	}
	Ok()

	// parse quote, log and attestation data
	Doing("Parsing quote")

	header := new(QuoteHeader)
	err = binary.Read(bytes.NewReader(data), binary.LittleEndian, header)
	if err != nil {
		Failed()
		return
	}

	rtmrLog := data[header.RtmrLogOffset:header.AttestOffset]
	attestData := data[header.AttestOffset:header.DataOffset]
	quote := data[header.DataOffset:]

	quoteStruct, err := attest.ParseQuote(quote)
	if err != nil {
		Failed()
		return
	}
	Ok()

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
	Doing("Verifying quote")

	verifierPath := filepath.Dir(os.Args[0]) + "/app"
	ok, err := attest.VerifyQuote(verifierPath, "./quote.bin")
	if !ok {
		Failed()
		return
	} else {
		Ok()
	}

	Doing("Parsing RTMR activity log")
	logs := strings.Split(string(rtmrLog[RtmrLog3:]), "\x00")
	logs = logs[:len(logs)-1]
	Ok()

	// check whether evaluated rtmr value and rtmr value from quote match
	Doing("Verifying RTMR activity log")
	mr := hex.EncodeToString(attest.GetRtmrValue(logs))
	r3 := quoteStruct.ReportBody.Rtmr[RtmrLog3]
	mrFromQuote := hex.EncodeToString(r3.M[:])
	if mr != mrFromQuote {
		Failed()
		//fmt.Fprintf(os.Stderr, "Evaluated: %v\n", mr)
		//fmt.Fprintf(os.Stderr, "From quote: %v\n", mrFromQuote)
		return
	} else {
		Passed()
		//fmt.Fprintf(os.Stderr, "RTMR value: %v\n", mr)
	}

	// check whether evaluated reportdata and the value from quote match
	Doing("Verifying ReportData")
	rd := sha512.Sum384(attestData)
	rdHex := hex.EncodeToString(rd[:])
	rdFromQuote := quoteStruct.ReportBody.ReportData
	rdFromQuoteHex := hex.EncodeToString(rdFromQuote.D[:sha512.Size384])
	if rdHex != rdFromQuoteHex {
		Failed()
		return
	} else {
		Passed()
	}

	// check whether there exists a 'Finalized' log entry
	Doing("Checking RTMR log against security policy")
	finalizedlogFound := false
	for _, e := range logs {
		if e == FinalizedLogEntry {
			finalizedlogFound = true
			break
		}
	}
	if !finalizedlogFound {
		Failed()
		fmt.Printf("\t%sERROR%s\tACON TD is not finalized\n", Red, NoColor)
		return
	}
	Passed()

	// dislay attestation related information
	Doing("Extracting attestation data")
	a, err := attest.ParseAttestData(attestData)
	if err != nil {
		Failed()
		return
	}
	Ok()

	//fmt.Println(string(attestData[:]))
	dumpAttestInfo(a)
}

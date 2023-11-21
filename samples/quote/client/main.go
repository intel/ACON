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
	"strings"

	"aconcli/attest"
)

const rtmrSize = sha512.Size384

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

func rtmr(logs []string) []byte {
	result := make([]byte, rtmrSize)
	for _, log := range logs {
		logSum := sha512.Sum384([]byte(log))
		result = append(result, logSum[:]...)
		sum := sha512.Sum384(result)
		result = sum[:]
	}
	return result
}

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("connect error:", err)
		return
	}
	defer conn.Close()

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

	ok, err := attest.VerifyQuote("./quote.bin")
	if !ok {
		fmt.Fprintf(os.Stderr, "verify quote failed, error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "verify quote successfully\n")
		return
	}

	logs := strings.Split(string(rtmrLog), "\n")
	logs = logs[:len(logs)-1]

	a, err := attest.ParseAttestData(attestData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse attest data error: %v\n", err)
		return
	}
	dumpAttestInfo(a)
	mr := rtmr(logs)
	fmt.Fprintf(os.Stdout, "RTMR value: %v\n", hex.EncodeToString(mr))
	return
}

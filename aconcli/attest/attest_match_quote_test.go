package attest

import (
	"encoding/hex"
	"flag"
	"os"
	"strings"
	"testing"
)

var rtmrlogs = flag.String("logs", "", "rtmr logs")
var quotefile = flag.String("quote", "quote.bin", "file path of binary quote")

func TestQuoteLogMatch(t *testing.T) {
	logs := strings.Split(*rtmrlogs, ",")
	mr := hex.EncodeToString(GetRtmrValue(logs))

	quote, err := os.ReadFile(*quotefile)
	if err != nil {
		t.Errorf("TestQuoteLogMatch, read quote error: %v", err)
	}
	quoteStruct, err := ParseQuote(quote)
	if err != nil {
		t.Errorf("TestQuoteLogMatch, parse quote error: %v", err)
	}
	r3 := quoteStruct.ReportBody.Rtmr[3]
	mrFromQuote := hex.EncodeToString(r3.M[:])
	if mr != mrFromQuote {
		t.Errorf("TestQuoteLogMatch, rtmr does not match")
	}
}

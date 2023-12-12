package attest

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

const (
	NUM_RTMRS = 4
	rtmrSize  = sha512.Size384
)

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
	TeeTcbInfoHash TeeMeasurement
	TeeInfoHash    TeeMeasurement
	ReportData     TeeReportData
	Reserved1      [32]byte
	Mac            [32]byte
}

type TeeTcbInfo struct {
	Data [239]byte
}

type TdInfo struct {
	Attributes    TeeAttributes             // TD's attributes
	Xfam          TeeAttributes             // TD's XFAM
	Mrtd          TeeMeasurement            // Measurement of initial contents of the TD
	MrConfigId    TeeMeasurement            // Software-defined ID for non-owner-defined configuration of the guest TD
	MrOwner       TeeMeasurement            // Software-defined ID for the guest TD's owner
	MrOwnerConfig TeeMeasurement            // Software-defined ID for owner-defined configuration of the guest TD
	Rtmr          [NUM_RTMRS]TeeMeasurement // Array of NUM_RTMRS(4) run-time extendable measurement registers
	ServTdHash    TeeMeasurement
	Reserved      [64]byte
}

type TeeMeasurement struct {
	M [48]byte
}

func (m TeeMeasurement) MarshalJSON() ([]byte, error) {
	src := m.M[:]
	return json.Marshal(hex.EncodeToString(src))
}
func (m TeeMeasurement) String() string {
	return hex.EncodeToString(m.M[:])
}

type TeeAttributes struct {
	A [2]uint32
}

func (a TeeAttributes) String() string {
	return fmt.Sprintf("%#x %#x", a.A[0], a.A[1])
}

type TeeReportData struct {
	D [64]byte
}

func (r TeeReportData) MarshalJSON() ([]byte, error) {
	src := r.D[:]
	//fmt.Println(hex.EncodeToString(src))
	return json.Marshal(hex.EncodeToString(src))
}

type SGXQuote4Header struct {
	Version    uint16   `json:"version"`
	AttKeyType uint16   `json:"-"`
	TeeType    uint32   `json:"teeType"`
	Reserved   uint32   `json:"-"`
	VendorId   [16]byte `json:"-"`
	UserData   [20]byte `json:"-"`
}

type SGXReport2Body struct {
	TeeTcbSvn      [16]byte                  `json:"-"`
	MrSeam         TeeMeasurement            `json:"-"`
	MrSignerSeam   TeeMeasurement            `json:"-"`
	SeamAttributes TeeAttributes             `json:"-"`
	TdAttributes   TeeAttributes             `json:"-"`
	Xfam           TeeAttributes             `json:"-"`
	MrTd           TeeMeasurement            `json:"-"`
	MrConfigId     TeeMeasurement            `json:"-"`
	MrOwner        TeeMeasurement            `json:"-"`
	MrOwnerConfig  TeeMeasurement            `json:"-"`
	Rtmr           [NUM_RTMRS]TeeMeasurement `json:"rtmr"`
	ReportData     TeeReportData             `json:"reportData"`
}

type SGXQuote4 struct {
	Header     SGXQuote4Header `json:"header"`
	ReportBody SGXReport2Body  `json:"reportBody"`
	SigDataLen uint32          `json:"-"`
	//SigData         []byte
}

type AttestData struct {
	ApiVersion      string                                `json:"api_version"`
	RequestorNonce  []byte                                `json:"requestor_nonce"`
	AcondNonce      []byte                                `json:"acond_nonce"`
	AttestationData map[string]map[uint32]AttestDataValue `json:"attestation_data"`
}

type AttestDataValue struct {
	Type int32  `json:"type"`
	Data string `json:"data"`
}

func ParseQuote(quote []byte) (*SGXQuote4, error) {
	quoteStruct := new(SGXQuote4)
	err := binary.Read(bytes.NewReader(quote), binary.LittleEndian, quoteStruct)
	if err != nil {
		return nil, fmt.Errorf("parse quote: %v", err)
	}
	return quoteStruct, nil
}

func ParseAttestData(data []byte) (*AttestData, error) {
	attestData := new(AttestData)
	err := json.Unmarshal(data, attestData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal attest data error: %v", err)
	}
	return attestData, nil
}

func WriteQuote(filename string, quote []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(quote)
	return err
}

func VerifyQuote(verifier, quote string) (bool, error) {
	cmd := exec.Command(verifier, "-quote", quote)
	if err := cmd.Run(); err != nil {
		return false, err
	} else {
		return true, nil
	}
}

func GetRtmrValue(logs []string) []byte {
	result := make([]byte, rtmrSize)
	for _, log := range logs {
		logSum := sha512.Sum384([]byte(log))
		result = append(result, logSum[:]...)
		sum := sha512.Sum384(result)
		result = sum[:]
	}
	return result
}

func VerifyRtmr(quote []byte, logs []string) (bool, error) {
	quoteStruct, err := ParseQuote(quote)
	if err != nil {
		return false, fmt.Errorf("verify rtmr error: %v", err)
	}
	mr := hex.EncodeToString(GetRtmrValue(logs))
	r := quoteStruct.ReportBody.Rtmr[3]
	mrFromQuote := hex.EncodeToString(r.M[:])
	if mr == mrFromQuote {
		return true, nil
	} else {
		return false, fmt.Errorf("rtmr does not match")
	}
}

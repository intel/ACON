package attest

import (
	"encoding/hex"
	"testing"
)

func TestGetRtmrValue(t *testing.T) {
	logsAndRtmrs := []struct {
		logs []string
		rtmr string
	}{
		{[]string{"INIT sha384/000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "github.com/intel/ACON AddManifest sha384/7ec795c3fe89687d4514a1e4f95b2421012fd0b877eba9d5d5f33a1314fe7e10a5b38b0890d890df59b716f55f41e2ff/1be479a625d00cc800da463a19baf111a5f69fa1858d78d124813236bc5b198bd551648273a0f65824b13490263362ef"},
			"e7d7d201073316d7e782aa1db45f91a572321053001fb67793d88351770e4c34552533409091748f39b367c5e254a013",
		},
	}

	for _, e := range logsAndRtmrs {
		result := hex.EncodeToString(GetRtmrValue(e.logs))
		if result != e.rtmr {
			t.Errorf("GetRtmrValue, want: %s, got: %s", e.rtmr, result)
		}
	}
}

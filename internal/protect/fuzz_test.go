package protect

import (
	"testing"

	"github.com/balyakin/crawlledger/internal/jsonstrict"
)

func FuzzProtectionConfig(fuzzer *testing.F) {
	fuzzer.Add([]byte(validConfigJSON))
	fuzzer.Add([]byte(`{"schema_version":1}`))
	fuzzer.Fuzz(func(t *testing.T, data []byte) {
		if int64(len(data)) > maxConfigBytes {
			return
		}
		var config Config
		if err := jsonstrict.Decode(data, &config); err == nil {
			_ = config.Validate()
		}
	})
}

func FuzzProtectionState(fuzzer *testing.F) {
	fuzzer.Add([]byte(`{"schema_version":1,"site":"example","config_sha256":"` + digestA +
		`","baseline_manifest_sha256":null,"rules":[]}`))
	fuzzer.Add([]byte(`{}`))
	fuzzer.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeState(data)
	})
}

func FuzzProtectionApplyPayload(fuzzer *testing.F) {
	fuzzer.Add([]byte(`{"schema_version":1,"site":"example","rules":[]}`))
	fuzzer.Add([]byte(`[]`))
	fuzzer.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeApplyPayload(data)
	})
}

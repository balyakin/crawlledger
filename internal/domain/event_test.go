package domain

import "testing"

func TestEventValidate(t *testing.T) {
	prefix := "/archive/"
	query := "0123456789abcdef0123456789abcdef"
	event := Event{
		TimestampUS:      1,
		ClientKey:        "0123456789abcdef0123456789abcdef",
		Method:           "GET",
		Route:            "/archive/{int}",
		ActionablePrefix: &prefix,
		URLFingerprint:   "0123456789abcdef0123456789abcdef",
		QueryKeys:        []string{"page"},
		QueryFingerprint: &query,
		Status:           200,
		BytesSent:        1,
		CacheState:       CacheUnknown,
		UAHash:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SecurityProbeIDs: []string{},
		PrimaryClass:     ClassUnclassified,
	}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	referer := "192.0.2.44"
	event.RefererHost = &referer
	if err := event.Validate(); err != nil {
		t.Fatalf("IP referer host rejected: %v", err)
	}
	event.QueryKeys = []string{"page", "page"}
	if err := event.Validate(); err == nil {
		t.Fatal("duplicate query key accepted")
	}
}

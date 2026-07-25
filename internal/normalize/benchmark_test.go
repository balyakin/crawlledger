package normalize

import (
	"net/netip"
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/parser"
)

func BenchmarkNormalize(b *testing.B) {
	normalizer := New(Key{1, 2, 3})
	record := parser.RawRecord{
		TimestampUS: 1784877072125000, ClientIP: netip.MustParseAddr("192.0.2.10"),
		Method: "GET", RequestURI: "/archive?page=42", Status: 200, BytesSent: 1234,
		CacheState: domain.CacheUnknown, UserAgent: "SyntheticBot/1.0",
		Referer: "https://docs.example/start",
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := normalizer.Normalize(record, Facts{}); err != nil {
			b.Fatal(err)
		}
	}
}

# CrawlLedger release evidence checklist

Record links or immutable artifact hashes for the candidate tag. This checklist records evidence; it never replaces a passing test.

- Candidate tag and clean commit:
- Go version (`go1.26.5`):
- Matrix CI run (Linux/macOS/Windows):
- `gofmt`, `go vet`, unit and race evidence:
- Eight 10-minute fuzz target artifacts:
- Pure-Go six-target build artifacts:
- JSON Schema and architecture guard evidence:
- Canonical/raw equivalence and recursive privacy scan:
- Immutable workspace and sidecar tamper tests:
- Nginx 1.30.4 `nginx -t` evidence:
- Caddy 2.11.4 adapt/validate evidence:
- Three cold and three warm 10 GiB benchmark logs:
- CPU, OS, kernel, filesystem, Go, exact command and corpus hashes:
- Analyze throughput/RSS min, median and max:
- One-million-cell simulation RSS:
- 200-clause target p99/throughput and zone saturation:
- Desktop, mobile and A4 synthetic report review:
- Private security contact published:
- README terminology and conditional commercial-offer audit:
- Reproducible archives and `checksums.txt`:
- Release changelog with schema/migration notes:

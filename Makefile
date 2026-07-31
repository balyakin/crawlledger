GO ?= go
FUZZ_PARALLEL ?= 4
BINARY := crawlledger
VERSION ?= dev
COMMIT ?= unknown
DATE ?= unknown
LDFLAGS := -s -w \
	-X github.com/balyakin/crawlledger/internal/version.Version=$(VERSION) \
	-X github.com/balyakin/crawlledger/internal/version.Commit=$(COMMIT) \
	-X github.com/balyakin/crawlledger/internal/version.Date=$(DATE)

.PHONY: fmt fmt-check vet test test-race fuzz-smoke build check clean

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))"

vet:
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

fuzz-smoke:
	$(GO) test ./internal/parser -run=^$$ -fuzz=FuzzNginxCombined -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/parser -run=^$$ -fuzz=FuzzNginxJSON -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/parser -run=^$$ -fuzz=FuzzCaddyJSON -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/parser -run=^$$ -fuzz=FuzzCanonicalJSON -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/parser -run=^$$ -fuzz=FuzzNginxProtection -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/normalize -run=^$$ -fuzz=FuzzNormalizePath -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/normalize -run=^$$ -fuzz=FuzzNormalizeQuery -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/policy -run=^$$ -fuzz=FuzzPolicyLoad -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/aggregate -run=^$$ -fuzz=FuzzKMVDecode -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/protect -run=^$$ -fuzz=FuzzProtectionConfig -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/protect -run=^$$ -fuzz=FuzzProtectionState -fuzztime=10s -parallel=$(FUZZ_PARALLEL)
	$(GO) test ./internal/protect -run=^$$ -fuzz=FuzzProtectionApplyPayload -fuzztime=10s -parallel=$(FUZZ_PARALLEL)

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/crawlledger

check: fmt-check vet test build

clean:
	$(GO) clean

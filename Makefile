# Quality gates and builds for conductor. GOWORK=off: the module is checked
# on its own (go.mod points at ../ad with a replace directive). Binaries are
# built with CGO off (pure-Go SQLite); the race detector needs cgo for tests.
export GOWORK := off
GOBIN := $(shell go env GOPATH)/bin
STATICCHECK := $(GOBIN)/staticcheck
GOVULNCHECK := $(GOBIN)/govulncheck
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test check fmt vet staticcheck vulncheck tools e2e-lab

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/conductor ./cmd/conductor
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/conductor-helper ./cmd/conductor-helper

test:
	go test -race ./...

check: fmt vet staticcheck vulncheck test

fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

staticcheck: tools
	$(STATICCHECK) ./...

vulncheck: tools
	$(GOVULNCHECK) ./...

tools:
	@test -x $(STATICCHECK) || go install honnef.co/go/tools/cmd/staticcheck@latest
	@test -x $(GOVULNCHECK) || go install golang.org/x/vuln/cmd/govulncheck@latest

# Build, install on the lab's dc1 and run the Playwright suite on
# server-home (planning/docs/lab.md, docs/usage-p1.md).
e2e-lab: build
	./e2e/run-lab.sh

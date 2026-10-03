# Quality gates and builds for conductor. Binaries are built with CGO off
# (pure-Go SQLite); the race detector needs cgo for tests.
# GOWORK=off by default: the module is checked on its own, against the
# versions go.mod pins (what CI and release builds use), not through a
# family go.work; `make check GOWORK=$PWD/../go.work` checks it against
# local copies of the sibling modules instead.
export GOWORK ?= off
GOBIN := $(shell go env GOPATH)/bin
STATICCHECK := $(GOBIN)/staticcheck
GOVULNCHECK := $(GOBIN)/govulncheck
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test check fmt vet staticcheck vulncheck tools e2e-lab package lintian

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
# the lab host (planning/docs/lab.md, docs/usage-p1.md).
e2e-lab: build
	./e2e/run-lab.sh

# Debian packages and their SBOMs in dist/ (amd64 and arm64 by default;
# version from the git tag, VERSION= overrides). Layout and release process:
# ../planning/docs/packaging.md.
ARCHES ?= amd64 arm64
package:
	packaging/build.sh $(ARCHES)

lintian:
	packaging/lintian.sh dist/*.deb

.PHONY: fmt lint test run tools

GOIMPORTS := $(shell command -v goimports 2>/dev/null)
GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null)

tools:
ifndef GOIMPORTS
	@echo "Installing goimports..."
	go install golang.org/x/tools/cmd/goimports@v0.16.1
endif
ifndef GOLANGCI_LINT
	@echo "Installing golangci-lint..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.56.2
endif

fmt: tools
	go fmt ./...
	goimports -w .

lint: tools
	golangci-lint run

test:
	go test ./...

run:
	go run cmd/server/main.go

.PHONY: help build test clean install run lint fmt coverage

help:
	@echo "GoScout - Secret Scanner"
	@echo ""
	@echo "Available targets:"
	@echo "  make build          - Build the goscout binary"
	@echo "  make test           - Run all tests"
	@echo "  make test-v         - Run tests with verbose output"
	@echo "  make coverage       - Generate coverage report"
	@echo "  make coverage-html  - Generate HTML coverage report"
	@echo "  make install        - Install goscout to /usr/local/bin"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make fmt            - Format code with gofmt"
	@echo "  make lint           - Run linter (requires golangci-lint)"
	@echo "  make run            - Run goscout on current directory"
	@echo "  make run-json       - Run goscout and output JSON"
	@echo "  make help           - Show this help message"

build:
	@echo "Building goscout..."
	go build -o goscout ./cmd/main.go
	@echo "✓ Build complete: ./goscout"

test:
	@echo "Running tests..."
	go test ./...
	@echo "✓ Tests passed"

test-v:
	@echo "Running tests with verbose output..."
	go test -v ./...


install: build
	@echo "Installing goscout..."
	sudo cp goscout /usr/local/bin/
	@echo "✓ goscout installed to /usr/local/bin/"

clean:
	@echo "Cleaning build artifacts..."
	rm -f goscout
	rm -f goscout-*
	go clean
	@echo "✓ Clean complete"

lint:
	@echo "Running linter..."
	golangci-lint run ./...

run: build
	@echo "Running goscout on current directory..."
	./goscout .

run-json: build
	@echo "Running goscout and outputting JSON..."
	./goscout . --json

test-scanner:
	@echo "Running scanner tests..."
	go test -v ./pkg/scanner/

test-utils:
	@echo "Running utils tests..."
	go test -v ./pkg/utils/

build-all: build
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build -o goscout-linux-amd64 ./cmd/goscout/main.go
	GOOS=darwin GOARCH=amd64 go build -o goscout-darwin-amd64 ./cmd/goscout/main.go
	GOOS=darwin GOARCH=arm64 go build -o goscout-darwin-arm64 ./cmd/goscout/main.go
	GOOS=windows GOARCH=amd64 go build -o goscout-windows-amd64.exe ./cmd/goscout/main.go
	@echo "✓ Multi-platform builds complete"

.DEFAULT_GOAL := help

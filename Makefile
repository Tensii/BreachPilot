BINARY=breachpilot

.PHONY: build test run

build:
	go build -o $(BINARY) ./cmd/breachpilot

test:
	go test ./...

run:
	go run ./cmd/breachpilot

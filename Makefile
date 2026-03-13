BINARY=breachpilot

.PHONY: build test run setup

build:
	go build -o $(BINARY) ./cmd/breachpilot

test:
	go test ./...

run:
	go run ./cmd/breachpilot

setup:
	go run ./cmd/breachpilot setup

BINARY=breachpilot

.PHONY: build test run setup sync-reconharvest sync-reconharvest-commit

build:
	go build -o $(BINARY) ./cmd/breachpilot

test:
	go test ./...

run:
	go run ./cmd/breachpilot

setup:
	go run ./cmd/breachpilot setup

sync-reconharvest:
	./tools/sync_reconharvest.sh

sync-reconharvest-commit:
	./tools/sync_reconharvest.sh
	git add tools/reconharvest/reconHarvest.py tools/reconharvest/installers.py
	git commit -m "chore(sync): update vendored reconHarvest from source repo" || true

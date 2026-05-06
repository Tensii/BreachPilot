SHELL := /bin/bash
BINARY=breachpilot
CRITICAL_PKGS=./internal/engine ./internal/exploit ./internal/exploit/httppolicy ./internal/notify
FLAKE_PKGS=./cmd/breachpilot ./internal/config ./internal/notify ./internal/exploit/httppolicy
COVERAGE_THRESHOLD=50

.PHONY: build test test-race test-race-critical test-flake coverage-critical vet ci run setup sync-reconharvest sync-reconharvest-latest sync-reconharvest-commit dashboard

build:
	go build -o $(BINARY) ./cmd/breachpilot

install: build
	@printf "\033[36m[*] Installing %s to /usr/local/bin...\033[0m\n" $(BINARY)
	sudo install -m 755 $(BINARY) /usr/local/bin/$(BINARY)
	@printf "\033[36m[*] Installing tools to /usr/local/share/breachpilot...\033[0m\n"
	sudo mkdir -p /usr/local/share/breachpilot
	sudo cp -rf --remove-destination tools /usr/local/share/breachpilot/
	@printf "\033[32m[✓] Installed successfully.\033[0m\n\n"
	@printf "\033[36m[*] Running initial setup and dependency check...\033[0m\n"
	@/usr/local/bin/$(BINARY) setup

uninstall:
	@printf "\033[31m[-] Removing %s from /usr/local/bin...\033[0m\n" $(BINARY)
	sudo rm -f /usr/local/bin/$(BINARY)
	@printf "\033[31m[-] Removing tools from /usr/local/share/breachpilot...\033[0m\n"
	sudo rm -rf /usr/local/share/breachpilot
	@printf "\033[32m[✓] Uninstalled successfully.\033[0m\n\n"

test:
	go test ./...

test-race:
	go test -race ./...

test-race-critical:
	go test -race $(CRITICAL_PKGS)

test-flake:
	go test -count=3 $(FLAKE_PKGS)

coverage-critical:
	./scripts/check_critical_coverage.sh $(COVERAGE_THRESHOLD)

vet:
	go vet ./...

ci: vet test build

run:
	go run ./cmd/breachpilot

setup:
	@printf "\033[36m[*] Setting up Python virtual environment...\033[0m\n"
	@python3 -m venv .venv || (printf "\033[31m[!] Failed to create venv. Is python3-venv installed?\033[0m\n" && exit 1)
	@.venv/bin/pip install --upgrade pip
	@.venv/bin/pip install -r requirements.txt
	@printf "\033[36m[*] Installing Frontend dependencies (npm)...\033[0m\n"
	@cd breachconsole/frontend && npm install
	@printf "\033[36m[*] Running Go tool setup...\033[0m\n"
	@go run ./cmd/breachpilot setup
	@printf "\033[32m[✓] Full setup complete.\033[0m\n"

sync-reconharvest:
	./tools/sync_reconharvest.sh

sync-reconharvest-latest:
	SYNC_PULL_LATEST=1 ./tools/sync_reconharvest.sh

sync-reconharvest-commit:
	./tools/sync_reconharvest.sh
	git add tools/reconharvest/reconHarvest.py tools/reconharvest/installers.py
	git commit -m "chore(sync): update vendored reconHarvest from source repo" || true

dashboard:
	@./scripts/start_dashboard.sh

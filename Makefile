
# Convenience targets; every one of them is a single command you can also
# run by hand (see README, "Build").

.DEFAULT_GOAL := help

GO ?= go
GOFMT ?= gofmt
BPFTOOL ?= bpftool
GOLANGCI_LINT ?= golangci-lint
RACE_CC ?= clang

.PHONY: help all build generate vmlinux test lint check clean

help: ## Show available commands.
	@printf 'Available commands:\n\n'
	@awk 'BEGIN { FS = ":.*## " } /^[a-zA-Z0-9_.-]+:.*## / { printf "  %-12s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

all: build ## Build the project.

# The binary. The generated bindings are committed, so this needs no clang.
build: ## Build the conn-monitor binary.
	$(GO) build -o bin/conn-monitor .

# Regenerate this kernel's types when explicitly requested.
vmlinux: ## Regenerate the kernel's vmlinux.h header.
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Generate the header automatically if it is missing.
bpf/vmlinux.h:
	@$(MAKE) --no-print-directory vmlinux

# Compile the kernel side and regenerate the Go bindings. Needs clang,
# llvm-strip, the libbpf headers and bpf/vmlinux.h.
generate: bpf/vmlinux.h ## Regenerate the Go bindings.
	$(GO) generate ./...

# The race detector requires cgo and a working C compiler.
test: ## Run tests with the race detector.
	CGO_ENABLED=1 CC=$(RACE_CC) $(GO) test -race -count=1 ./...

# golangci-lint reads .golangci.yml.
lint: ## Run golangci-lint.
	$(GOLANGCI_LINT) run ./...

# What CI runs: formatting, vet, tests.
check: ## Run formatting checks, vet, and tests.
	@unformatted="$$(find . -type d \( -name .tools -o -name .git \) -prune -o -type f -name '*.go' -exec $(GOFMT) -l {} +)" || exit 1; \
	if [ -n "$$unformatted" ]; then \
		printf '%s\n' "$$unformatted"; \
		echo "gofmt: files above need formatting"; \
		exit 1; \
	fi
	$(GO) vet ./...
	@$(MAKE) --no-print-directory test

clean: ## Remove the compiled binary.
	rm -f bin/conn-monitor

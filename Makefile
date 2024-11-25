SHELL=/bin/bash
.DEFAULT_GOAL := all
MAKEFLAGS += --no-print-directory

.PHONY: all
all: lint unit_tests benchmark_tests

.PHONY: lint
lint:
	bash ./scripts/lint.sh

.PHONY: unit_tests
unit_tests:
	bash ./scripts/unittests.sh $(VERBOSE)

.PHONY: benchmark_tests
benchmark_tests:
	bash ./scripts/benchtests.sh

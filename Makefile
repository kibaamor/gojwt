SHELL=/bin/bash

all: lint unit_tests benchmark_tests

##########################
# Validations            #
##########################

lint:
	bash ./scripts/lint.sh

##########################
# Tests                  #
##########################

unit_tests:
	bash ./scripts/unittests.sh $(VERBOSE)

##########################
# Benchmark              #
##########################

benchmark_tests:
	 bash ./scripts/benchtests.sh

.PHONY: all lint unit_tests benchmark_tests
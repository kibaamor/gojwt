SHELL=/bin/bash

all: validate benchmark_tests

##########################
# Validations            #
##########################

lint:
	bash ./build/lint.sh

##########################
# Tests                  #
##########################

unit_tests:
	@echo "Execute unit tests..."
	bash ./build/unittests.sh $(VERBOSE)

##########################
# Benchmark              #
##########################

benchmark_tests:
	 bash ./build/benchtests.sh

validate: lint unit_tests

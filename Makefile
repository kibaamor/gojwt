SHELL=/bin/bash

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

##########################
# Validations            #
##########################

lint:
	bash ./build/lint.sh

validate: lint unit_tests

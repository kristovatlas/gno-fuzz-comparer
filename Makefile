# Define the log and directory paths
LOG_FILE = fuzzer.log
FUZZER_DIR = fuzzer

# Default target
.PHONY: all
all:
	@echo "Run 'make clean' to delete logs and generated files."

# Clean target
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(LOG_FILE)                         # Remove the fuzzer.log file
	rm -rf $(FUZZER_DIR)                       # Remove the fuzzer/ directory and all its contents
	@echo "Clean complete."

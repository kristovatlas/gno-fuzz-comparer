# gno-fuzz-comparer
A tool that executes fuzzed input against various `gno` and `go` command line tools, and compares their output for discrepancies to find bugs.

Currently this only supports a simple deterministic fuzzer that spams `go mody tidy` and `gno mod tidy` with a range of unicode characters to find differences in how they parse modfiles. In the future, this can be extended to do other kinds of fuzzing against these targets, as well as adding new targets. Related gno issue: https://github.com/gnolang/gno/issues/2426

The program is multi-threaded to speed along progress.

# Requirements

You must have appropriate versions of `go` and `gno` installed.

# Usage

```bash
% make clean
Cleaning up...
rm -f fuzzer.log                         # Remove the fuzzer.log file
rm -rf fuzzer                       # Remove the fuzzer/ directory and all its contents

% go run fuzzer.go -threads=8
3712 iterations to compute...
[==================================================] 100.00% | 3712/3712 | 104.02 it/s | ETA: 0s

--- Summary ---
go mod tidy: UnknownDirective: 61, Parsing Error: 3591, Success: 57, Other: 0
gno mod tidy: UnknownDirective: 61, Parsng Error: 3651, Success: 0, Other: 0
Investigate fuzzer.log for discrepancies between `go mod tidy` and `gno mod tiny` output, and any entries under 'Other' here may indicate missing parsing logic.
```

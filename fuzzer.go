package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	baseDir    = "fuzzer"
	initialMod = `module example.com/myproject
go 1.20
require (
    github.com/stretchr/testify v1.8.4
    golang.org/x/sync v0.1.0
)`
	outputLog = "fuzzer.log"
)

type UnicodeRange struct {
	Start rune
	End   rune
}

var unicodeRanges = []UnicodeRange{
	{0x0000, 0x001F}, // Control Characters
	//{0xD800, 0xDFFF},     // Surrogate Pairs
	//{0x010000, 0x10FFFF}, // Non-BMP Characters
	//{0x0300, 0x036F},   // Combining Characters
	//{0xFE00, 0xFE0F},   // Variation Selectors
	//{0x200B, 0x200D},   // Zero Width Characters
	//{0x2060, 0x2060},   // Zero Width Non-Breaking Space
	//{0xE000, 0xF8FF},   // Private Use Area
	//{0x1F600, 0x1F64F}, // Emoticons
	//{0x1F680, 0x1F6FF}, // Transport and Map Symbols
	//{0x200E, 0x200F},   // Bidirectional Control Characters
	//{0x202A, 0x202E},   // Additional Bidirectional Controls
	//{0x1D400, 0x1D7FF}, // Mathematical and Technical Symbols
}

// Define an enum-like type for command output categories
type OutputCategory int

const (
	UnknownDirective OutputCategory = iota
	UnknownError
	Success
	Other
)

var (
	goUnknownDirectiveCount int
	goErrorCount            int
	goSuccessCount          int
	goOtherCount            int

	gnoUnknownDirectiveCount int
	gnoErrorCount            int
	gnoSuccessCount          int
	gnoOtherCount            int
)

// Generate a slice of all characters in the defined Unicode ranges
func generateAllChars() []rune {
	var allChars []rune
	for _, r := range unicodeRanges {
		for ch := r.Start; ch <= r.End; ch++ {
			allChars = append(allChars, ch)
		}
	}
	return allChars
}

func main() {
	threads := flag.Int("threads", 1, "Maximum number of concurrent threads")
	flag.Parse()

	if *threads <= 0 {
		log.Fatalf("Invalid number of threads: %d", *threads)
	}

	// Create base fuzzer directory
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		log.Fatalf("Failed to create base directory: %v", err)
	}

	logFile, err := os.OpenFile(outputLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)

	if err := fuzzConcurrently(logger, initialMod, *threads); err != nil {
		log.Fatalf("Fuzzing failed: %v", err)
	}

	printResults()
}

func fuzzConcurrently(logger *log.Logger, modFileContent string, maxThreads int) error {
	fuzzingChars := generateAllChars()
	totalIterations := len(modFileContent) * len(fuzzingChars)
	fmt.Printf("%d iterations to compute...\n", totalIterations)

	startTime := time.Now()
	lastUpdate := startTime
	updateInterval := 1 * time.Second

	var currentIteration int
	var mu sync.Mutex
	wg := sync.WaitGroup{}
	tasks := make(chan int, totalIterations)

	for i := 0; i < len(modFileContent); i++ {
		for _, r := range fuzzingChars {
			tasks <- i<<16 | int(r) // Pack `i` and `r` into a single integer
		}
	}
	close(tasks)

	for t := 0; t < maxThreads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				i := task >> 16
				r := rune(task & 0xFFFF)

				// Mutate content
				mutatedContent := []rune(modFileContent)
				mutatedContent[i] = r

				// Create test directory
				testDir := filepath.Join(baseDir, fmt.Sprintf("test%d_%d", i, r))
				if err := os.MkdirAll(testDir, 0755); err != nil {
					log.Printf("Failed to create test directory: %v", err)
					continue
				}

				goModPath := filepath.Join(testDir, "go.mod")
				gnoModPath := filepath.Join(testDir, "gno.mod")
				if err := writeFile(goModPath, string(mutatedContent)); err != nil {
					log.Printf("Failed to write go.mod: %v", err)
					continue
				}
				if err := writeFile(gnoModPath, string(mutatedContent)); err != nil {
					log.Printf("Failed to write gno.mod: %v", err)
					continue
				}

				goOutput, _ := runCommand("go", []string{"mod", "tidy"}, testDir)
				gnoOutput, _ := runCommand("gno", []string{"mod", "tidy"}, testDir)

				if !compareOutputs(goOutput, gnoOutput) {
					logger.Printf("Discrepancy detected in %s\n", testDir)
					logger.Printf("go output: %s", goOutput)
					logger.Printf("gno output: %s", gnoOutput)
					logger.Printf("modfile start ----\n%s\nmodfile end----\n", string(mutatedContent))
				}

				// Update progress
				mu.Lock()
				currentIteration++
				now := time.Now()
				if now.Sub(lastUpdate) >= updateInterval || currentIteration == totalIterations {
					lastUpdate = displayProgress(currentIteration, totalIterations, startTime, lastUpdate, updateInterval)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return nil
}

func categorizeOutput(output string, commandType string) OutputCategory {
	output = strings.TrimSpace(output)

	if strings.Contains(output, "unknown directive") {
		if commandType == "go" {
			goUnknownDirectiveCount++
		} else if commandType == "gno" {
			gnoUnknownDirectiveCount++
		}
		return UnknownDirective
	}

	if strings.Contains(output, "error parsing") || strings.Contains(output, "errors parsing") {
		if commandType == "go" {
			goErrorCount++
		} else if commandType == "gno" {
			gnoErrorCount++
		}
		return UnknownError
	}

	// If the command appears to succeed (indicating a success state)
	if output == "" || output == "go: warning: \"all\" matched no packages" {
		if commandType == "go" {
			goSuccessCount++
		} else if commandType == "gno" {
			gnoSuccessCount++
		}

		return Success
	}

	if commandType == "go" {
		goOtherCount++
	} else if commandType == "gno" {
		gnoOtherCount++
	}
	return Other
}

func compareOutputs(goOutput string, gnoOutput string) bool {
	// Categorize the outputs
	goCategory := categorizeOutput(goOutput, "go")
	gnoCategory := categorizeOutput(gnoOutput, "gno")

	// Compare categories
	return goCategory == gnoCategory
}

// displayProgress prints a progress bar to the console
func displayProgress(current, total int, startTime, lastUpdate time.Time, updateInterval time.Duration) time.Time {
	now := time.Now()
	if now.Sub(lastUpdate) < updateInterval && current < total {
		return lastUpdate
	}

	elapsed := now.Sub(startTime)
	iterationsPerSecond := float64(current) / elapsed.Seconds()
	remainingIterations := total - current
	estimatedTimeRemaining := time.Duration(float64(remainingIterations)/iterationsPerSecond) * time.Second

	percentage := float64(current) / float64(total) * 100
	barLength := 50
	filledLength := int(percentage / 100 * float64(barLength))

	bar := fmt.Sprintf("[%s%s] %.2f%% | %d/%d | %.2f it/s | ETA: %s",
		strings.Repeat("=", filledLength),
		strings.Repeat(" ", barLength-filledLength),
		percentage,
		current, total,
		iterationsPerSecond,
		estimatedTimeRemaining.Round(time.Second),
	)

	fmt.Printf("\r%s", bar)
	os.Stdout.Sync()
	if current == total {
		fmt.Println()
	}

	return now
}

func printResults() {
	fmt.Println("\n--- Summary ---")
	fmt.Printf("go mod tidy: UnknownDirective: %d, Parsing Error: %d, Success: %d, Other: %d\n",
		goUnknownDirectiveCount, goErrorCount, goSuccessCount, goOtherCount)
	fmt.Printf("gno mod tidy: UnknownDirective: %d, Parsng Error: %d, Success: %d, Other: %d\n",
		gnoUnknownDirectiveCount, gnoErrorCount, gnoSuccessCount, gnoOtherCount)
	fmt.Println("Investigate fuzzer.log for discrepancies between `go mod tidy` and `gno mod tiny` output, and any entries under 'Other' here may indicate missing parsing logic.")
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func runCommand(cmdName string, args []string, workDir string) (string, error) {
	cmd := exec.Command(cmdName, args...)
	cmd.Dir = workDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func mutateModFile(original string) []string {
	var mutatedFiles []string
	runes := []rune(original)
	allChars := generateAllChars()

	for i := 0; i < len(runes); i++ {
		originalRune := runes[i]
		for _, newChar := range allChars {
			runes[i] = newChar
			mutatedFiles = append(mutatedFiles, string(runes))
		}
		// Restore the original character
		runes[i] = originalRune
	}

	return mutatedFiles
}

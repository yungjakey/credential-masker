package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	cp "github.com/otiai10/copy"
)

// finding represents a credential or secret finding from gitleaks
type finding struct {
	RuleID      string  `json:"ruleID"`      // ID of the rule that triggered this finding
	StartLine   int     `json:"startLine"`   // Line where the finding starts
	EndLine     int     `json:"endLine"`     // Line where the finding ends
	Match       string  `json:"match"`       // The matched text containing the secret
	Secret      string  `json:"secret"`      // The actual secret value
	File        string  `json:"file"`        // Path to the file containing the secret
	Entropy     float64 `json:"entropy"`     // Entropy score of the secret
	Fingerprint string  `json:"fingerprint"` // Unique identifier for this finding
}

// printUsage displays help information about command usage
func printUsage() {
	fmt.Println("Credential Masker - A tool to mask credentials in source code")
	fmt.Println("\nUsage:")
	fmt.Println("  credential-masker [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --source     Source directory containing original code")
	fmt.Println("  --target     Target directory where masked code will be written")
	fmt.Println("  --findings   Path to gitleaks JSON findings file")
	fmt.Println("  --log-level  Log level (DEBUG, INFO, SUCCESS, WARNING, ERROR, FATAL) [default: INFO]")
	fmt.Println("  --help       Display this help message")
	fmt.Println("\nExample:")
	fmt.Println("  credential-masker --source ./myproject --target ./masked-project --findings ./gitleaks.json")
}

// loadFindings loads and parses the findings JSON file
func loadFindings(path string) ([]finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading findings JSON: %v", err)
	}

	var findings []finding
	err = json.Unmarshal(raw, &findings)
	if err != nil {
		return nil, fmt.Errorf("error parsing JSON: %v", err)
	}

	return findings, nil
}

// watcher monitors for termination signals and cancels the main context
func watcher(cancel context.CancelFunc, logger *Logger) {
	// Setup signal handling
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-signalChan
	logger.Info("Received signal: %s", sig)
	logger.Info("Gracefully shutting down...")

	cancel() // Cancel the main context
}

func main() {
	// Check for help flag first
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			printUsage()
			return
		}
	}

	// Parse and validate flags - this also sets up the logger
	cfg, err := parseAndValidateFlags()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		printUsage()
		os.Exit(1)
	}
	log := cfg.logger

	// Create a context that can be canceled
	ctx, cancel := context.WithCancel(context.Background())

	// Run the signal handler in a goroutine
	go watcher(cancel, log)

	// Create a channel to signal completion
	done := make(chan struct{})

	// Run the main processing in a goroutine
	go func() {
		defer close(done)

		findings, err := loadFindings(cfg.findingsPath)
		if err != nil {
			log.Fatal("%v", err)
		}

		// Print all unique types of findings
		uniqueTypes := make(map[string]bool)
		for _, f := range findings {
			uniqueTypes[f.RuleID] = true
		}

		log.Debug("Unique types of findings:")
		for t := range uniqueTypes {
			log.Debug("  - %s", t)
		}

		// Check if the target directory exists
		if _, err = os.Stat(cfg.targetDir); os.IsNotExist(err) {
			log.Info("Target directory does not exist, creating: %s", cfg.sourceDir)

			// Copy the source directory to the target directory
			if err = cp.Copy(cfg.sourceDir, cfg.targetDir); err != nil {
				log.Fatal("%v", err)
			}
			log.Success("Copied %s to %s", cfg.sourceDir, cfg.targetDir)
		} else {
			log.Info("Target directory already exists: %s", cfg.targetDir)
		}

		// Create a new Masker with findings and directories
		masker := NewMasker(cfg.sourceDir, cfg.targetDir, findings, log)

		// Process all findings with context
		fileFindings := masker.ProcessWithContext(ctx)

		// Check if context was canceled
		if ctx.Err() != nil {
			log.Warning("Processing was interrupted: %v", ctx.Err())
			return
		}

		log.Success("Processed %d findings", len(findings))

		// Save file findings to JSON
		fileFindingsJSON, err := json.MarshalIndent(fileFindings, "", "  ")
		if err != nil {
			log.Fatal("Error marshalling file findings to JSON: %v", err)
		}

		outputPath := strings.NewReplacer("gitleaks", "gitleaks-grouped").Replace(cfg.findingsPath)
		err = os.WriteFile(outputPath, fileFindingsJSON, 0600)
		if err != nil {
			log.Fatal("Error writing file findings to JSON: %v", err)
		}
		log.Success("Saved file findings to %s", outputPath)
	}()

	// Wait for either completion or context cancellation
	select {
	case <-done:
		// Processing completed normally
	case <-ctx.Done():
		// Context was canceled, wait for graceful shutdown
		select {
		case <-done:
			// Processing completed during graceful shutdown
		case <-time.After(5 * time.Second):
			log.Warning("Shutdown timed out after 5 seconds")
		}
		os.Exit(1)
	}
}

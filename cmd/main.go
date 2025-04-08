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

// stores gitleaks json
type finding struct {
	RuleID      string  `json:"ruleID"`
	StartLine   int     `json:"startLine"`
	EndLine     int     `json:"endLine"`
	Match       string  `json:"match"`
	Secret      string  `json:"secret"`
	File        string  `json:"file"`
	Entropy     float64 `json:"entropy"`
	Fingerprint string  `json:"fingerprint"`
}

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

func main() {
	// Parse and validate flags - this also sets up the logger
	cfg, err := parseAndValidateFlags()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	log := cfg.logger

	// Create a context that can be canceled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Run the signal handler in a goroutine
	go func() {
		sig := <-signalChan
		log.Info("Received signal: %s", sig)
		log.Info("Gracefully shutting down...")

		// Create a timeout context for graceful shutdown
		_, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelTimeout()

		cancel() // Cancel the main context
	}()

	findings, err := loadFindings(cfg.findingsPath)
	if err != nil {
		log.Fatal("%v", err)
	}

	// Print all unique types of findings
	uniqueTypes := map[string]bool{}
	for _, f := range findings {
		uniqueTypes[f.RuleID] = true
	}

	log.Info("Unique types of findings:")
	for t := range uniqueTypes {
		log.Debug("  - %s", t)
	}

	// Check if the target directory exists
	if _, err = os.Stat(cfg.targetDir); os.IsNotExist(err) {
		log.Info("Target directory does not exist, recreating: %s", cfg.sourceDir)

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
		os.Exit(1)
	}

	log.Success("Processed %d findings", len(findings))

	// Save file findings to JSON
	fileFindingsJSON, err := json.MarshalIndent(fileFindings, "", "  ")
	if err != nil {
		log.Fatal("Error marshalling file findings to JSON: %v", err)
	}

	outputPath := strings.NewReplacer("gitleaks", "gitleaks-grouped").Replace(cfg.findingsPath)
	err = os.WriteFile(outputPath, fileFindingsJSON, 0644)
	if err != nil {
		log.Fatal("Error writing file findings to JSON: %v", err)
	}
	log.Success("Saved file findings to %s", outputPath)
}

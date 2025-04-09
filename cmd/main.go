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
	ID          string  `json:"id"`          // Unique ID for this finding
}

// printUsage displays help information about command usage
func printUsage() {
	fmt.Println("Credential Masker - A tool to mask credentials in source code")
	fmt.Println("\nUsage:")
	fmt.Println("  credential-masker [flags]")
	fmt.Println("\nFlags:")
	fmt.Println("  --source            Source directory containing original code")
	fmt.Println("  --target            Target directory where masked code will be written")
	fmt.Println("  --findings          Path to gitleaks JSON findings file")
	fmt.Println("  --log-level         Log level (DEBUG, INFO, SUCCESS, WARNING, ERROR, FATAL) [default: INFO]")
	fmt.Println("  --mask              Placeholder text for masked credentials [default: ***[REDACTED]***]")
	fmt.Println("  --newline           Newline sequence to use when writing files [default: \\r\\n]")
	fmt.Println("  --shutdown-timeout  Timeout in seconds for graceful shutdown [default: 5]")
	fmt.Println("  --help              Display this help message")
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

func main() {
	cfg, err := parseAndValidateFlags()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		printUsage()
		os.Exit(1)
	}

	if cfg.showHelp {
		printUsage()
		return
	}

	log := cfg.logger

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})

	go func() {
		defer close(done)

		findings, err := loadFindings(cfg.findingsPath)
		if err != nil {
			log.Fatal("%v", err)
		}

		uniqueTypes := make(map[string]bool)
		for _, f := range findings {
			uniqueTypes[f.RuleID] = true
		}
		log.Debug("Unique types of findings:")
		for t := range uniqueTypes {
			log.Debug("  - %s", t)
		}

		if _, err = os.Stat(cfg.targetDir); os.IsNotExist(err) {
			log.Info("Target directory does not exist, creating: %s", cfg.sourceDir)
			if err = cp.Copy(cfg.sourceDir, cfg.targetDir); err != nil {
				log.Fatal("%v", err)
			}
			log.Success("Copied %s to %s", cfg.sourceDir, cfg.targetDir)
		} else {
			log.Info("Target directory already exists: %s", cfg.targetDir)
		}

		masker := NewMasker(
			cfg.sourceDir,
			cfg.targetDir,
			findings,
			cfg.placeholderMask,
			cfg.newLineSequence,
			log,
		)

		fileFindings := masker.ProcessWithContext(ctx)

		if ctx.Err() != nil {
			log.Warning("Processing was interrupted: %v", ctx.Err())
			return
		}

		log.Success("Processed %d findings", len(findings))

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

	select {
	case <-done:
		// All good
		return
	case <-ctx.Done():
		log.Warning("Shutdown signal received, waiting up to %v for graceful shutdown...", cfg.shutdownTimeout)
	}

	// Now wait for completion or timeout AFTER signal, no nested select
	timer := time.NewTimer(cfg.shutdownTimeout)
	defer timer.Stop()

	select {
	case <-done:
		log.Info("Graceful shutdown completed in time")
	case <-timer.C:
		log.Error("Shutdown timeout exceeded. Forcing exit.")
		os.Exit(1)
	}
}

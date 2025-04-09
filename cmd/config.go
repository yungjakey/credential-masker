package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"time"
)

type Config struct {
	findingsPath    string
	sourceDir       string
	targetDir       string
	logger          *Logger
	showHelp        bool
	shutdownTimeout time.Duration
	placeholderMask string
	newLineSequence string
}

// setupUsage creates a custom usage function that prints help information
func setupUsage() {
	flag.Usage = func() {
		fmt.Println("Credential Masker - A tool to mask credentials in source code")
		fmt.Println("\nUsage:")
		fmt.Println("  credential-masker [flags]")
		fmt.Println("\nFlags:")

		// Define the custom order of flags
		orderedFlags := []string{"source", "target", "findings", "mask", "newline", "shutdown-timeout", "log-level", "help"}

		// Print flags in the specified order
		for _, name := range orderedFlags {
			f := flag.Lookup(name)
			if f == nil {
				continue
			}

			defaultValue := f.DefValue
			if f.Name == "mask" {
				// Special handling for mask to escape % characters
				defaultValue = fmt.Sprintf("%q", defaultValue)
			}
			fmt.Printf("  --%-18s %s [default: %v]\n", f.Name, f.Usage, defaultValue)
		}

		fmt.Println("\nExample:")
		fmt.Println("  credential-masker --source ./myproject --target ./masked-project --findings ./gitleaks.json")
	}
}

func parseAndValidateFlags() (*Config, error) {
	// Setup custom usage function before defining flags
	setupUsage()

	// Flag definitions here serve as the single source of truth for default values
	findingsPath := flag.String("findings", "reports/arcon_formulare.gitleaks.json", "Path to Gitleaks findings JSON file")
	sourceDir := flag.String("source", "external/source/arcon_formulare", "Path to source repository")
	targetDir := flag.String("target", "external/target/arcon_formulare", "Path to target repository for masked files")
	shutdownTimeout := flag.Int("shutdown-timeout", 15, "Timeout in seconds for graceful shutdown")
	placeholderMask := flag.String("mask", "***MASKED[\"%s__%s__%s\"]***", "Placeholder text for masked credentials. To be filled with 1. file prefix 2. finding ID 3. finding UUID")
	newLineSequence := flag.String("newline", "\\r\\n", "Newline sequence to use when writing files")
	logLevelStr := flag.String("log-level", "INFO", "Log level (DEBUG, INFO, SUCCESS, WARNING, ERROR, FATAL)")
	showHelp := flag.Bool("help", false, "Display help information")

	flag.Parse()

	if *showHelp {
		flag.Usage()
		return &Config{showHelp: true}, nil
	}

	if *sourceDir == "" {
		return nil, fmt.Errorf("missing required flag: --source")
	}
	if *targetDir == "" {
		return nil, fmt.Errorf("missing required flag: --target")
	}
	if *findingsPath == "" {
		return nil, fmt.Errorf("missing required flag: --findings")
	}

	// Parse log level
	logLevel, err := ParseLogLevel(*logLevelStr)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %v", err)
	}

	// Create logger with Configured log level
	logger := Default()
	logger.SetMinLevel(logLevel)

	// Clean all paths
	cleanSourceDir := filepath.Clean(*sourceDir)
	cleanTargetDir := filepath.Clean(*targetDir)
	cleanFindingsPath := filepath.Clean(*findingsPath)

	return &Config{
		findingsPath:    cleanFindingsPath,
		sourceDir:       cleanSourceDir,
		targetDir:       cleanTargetDir,
		logger:          logger,
		showHelp:        *showHelp,
		shutdownTimeout: time.Duration(*shutdownTimeout) * time.Second,
		placeholderMask: *placeholderMask,
		newLineSequence: *newLineSequence,
	}, nil
}

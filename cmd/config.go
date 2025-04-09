package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"time"
)

type config struct {
	findingsPath    string
	sourceDir       string
	targetDir       string
	logger          *Logger
	showHelp        bool
	shutdownTimeout time.Duration
	placeholderMask string
	newLineSequence string
}

func parseAndValidateFlags() (*config, error) {
	findingsPath := flag.String("findings", "reports/arcon_formulare.gitleaks.json", "Path to Gitleaks findings JSON file")
	sourceDir := flag.String("source", "external/source/arcon_formulare", "Path to source repository")
	targetDir := flag.String("target", "external/target/arcon_formulare", "Path to target repository for masked files")
	logLevelStr := flag.String("log-level", "INFO", "Log level (DEBUG, INFO, SUCCESS, WARNING, ERROR, FATAL)")
	shutdownTimeout := flag.Int("shutdown-timeout", 15, "Timeout in seconds for graceful shutdown")
	placeholderMask := flag.String("mask", "***[REDACTED]***", "Placeholder text for masked credentials")
	newLineSequence := flag.String("newline", "\r\n", "Newline sequence to use when writing files")
	showHelp := flag.Bool("help", false, "Display help information")
	flag.BoolVar(showHelp, "h", false, "Display help information (shorthand)")

	flag.Parse()

	if *showHelp {
		flag.Usage()
		return nil, nil
	}

	if *findingsPath == "" {
		return nil, fmt.Errorf("missing required flag: --findings")
	}
	if *sourceDir == "" {
		return nil, fmt.Errorf("missing required flag: --source")
	}
	if *targetDir == "" {
		return nil, fmt.Errorf("missing required flag: --target")
	}

	// Parse log level
	logLevel, err := ParseLogLevel(*logLevelStr)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %v", err)
	}

	// Create logger with configured log level
	logger := Default()
	logger.SetMinLevel(logLevel)

	// Clean all paths
	cleanSourceDir := filepath.Clean(*sourceDir)
	cleanTargetDir := filepath.Clean(*targetDir)
	cleanFindingsPath := filepath.Clean(*findingsPath)

	return &config{
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

package main

import (
	"flag"
	"fmt"
	"path/filepath"
)

type config struct {
	findingsPath string
	sourceDir    string
	targetDir    string
	logger       *Logger
}

func parseAndValidateFlags() (*config, error) {
	findingsPath := flag.String("findings", "reports/arcon_formulare.gitleaks.json", "Path to Gitleaks findings JSON file")
	sourceDir := flag.String("source", "external/source/arcon_formulare", "Path to source repository")
	targetDir := flag.String("target", "external/target/arcon_formulare", "Path to target repository for masked files")
	logLevelStr := flag.String("log-level", "INFO", "Log level (DEBUG, INFO, SUCCESS, WARNING, ERROR, FATAL)")

	flag.Parse()

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
		findingsPath: cleanFindingsPath,
		sourceDir:    cleanSourceDir,
		targetDir:    cleanTargetDir,
		logger:       logger,
	}, nil
}

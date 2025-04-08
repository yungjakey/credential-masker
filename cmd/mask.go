package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"
)

const placeholderPrefix = "This file was deleted because it matched the pkcs12-file rule. Original file: %s"
const placeholderMask = "***[REDACTED]***"

type chunk struct {
	startLine int
	endLine   int
	match     string
	content   []string // Lines in this chunk
}

type result struct {
	startLine int
	endLine   int
	content   []string // Processed lines
}

// Masker handles the masking of sensitive data in files
type Masker struct {
	logger    *Logger
	findings  map[string][]finding // Map of file path to findings
	results   map[string]bool      // Map of file path to processing result
	sourceDir string
	targetDir string
}

// NewMasker creates a new Masker with the given logger
func NewMasker(sourceDir string, targetDir string, findings []finding, logger *Logger) *Masker {
	// Group findings by file
	fileFindings := make(map[string][]finding)
	for _, f := range findings {
		// replace source and target directory
		path := strings.NewReplacer(sourceDir, targetDir).Replace(f.File)
		fileFindings[path] = append(fileFindings[path], f)
	}

	return &Masker{
		logger:    logger,
		findings:  fileFindings,
		results:   make(map[string]bool),
		sourceDir: sourceDir,
		targetDir: targetDir,
	}
}

// Process processes all findings across files
func (m *Masker) Process() map[string][]finding {
	// Walk findings by file
	for path, fileFinding := range m.findings {
		m.logger.Info("Checking findings in %s", path)

		// Check if any findings
		if len(fileFinding) == 0 {
			m.logger.Success("Nothing to do. File %s has no findings.", path)
			m.results[path] = true
			continue
		}

		// Get appropriate file handler
		handler, err := m.ParseFileType(path, fileFinding)
		if err != nil {
			m.logger.Error("Error parsing type of file: %v", err)
			m.results[path] = false
			continue
		}
		if handler == nil {
			m.logger.Success("Nothing to do. File %s is empty.", path)
			m.results[path] = true
			continue
		}

		// Handle file
		err = handler()
		if err != nil {
			m.logger.Error("Error handling file: %v", err)
			m.results[path] = false
			continue
		}

		m.results[path] = true
		m.logger.Success("Handled %d finding(s)", len(fileFinding))
	}

	return m.findings
}

// GetResults returns the processing results
func (m *Masker) GetResults() map[string]bool {
	return m.results
}

// ParseFileType determines the appropriate handler for a file based on its contents and findings
func (m *Masker) ParseFileType(path string, fileFinding []finding) (func() error, error) {
	// First see if any finding matches the pkcs12-file rule
	for _, f := range fileFinding {
		if f.RuleID == "pkcs12-file" {
			m.logger.Debug("Matched pkcs12-file rule.")
			return func() error {
				return m.HandleBinary(path)
			}, nil
		}
	}

	// Read file
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err // noop
	}

	// Check if file is empty
	if len(buf) == 0 {
		return nil, nil // noop
	}

	// Check if file valid utf
	if !utf8.Valid(buf) {
		m.logger.Debug("Invalid UTF-8.")
		return func() error {
			return m.HandleBinary(path)
		}, nil
	}

	return func() error {
		return m.HandleText(buf, fileFinding...)
	}, nil
}

// RecreateFile recreates a file with the given lines
func (m *Masker) RecreateFile(path string, lines ...string) error {
	m.logger.Debug("Recreating file")

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("Error deleting file: %v", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Error creating empty file: %v", err)
	}
	defer f.Close()

	if len(lines) > 0 {
		content := strings.Join(lines, "\n")
		if _, err := f.WriteString(content); err != nil {
			return fmt.Errorf("Error writing to file: %v", err)
		}
	}
	return nil
}

// HandleBinary processes binary files with sensitive data
func (m *Masker) HandleBinary(path string) error {
	var err error

	// Recreate file to remove its contents
	if err = m.RecreateFile(path); err != nil {
		return fmt.Errorf("Error recreating file: %v", err)
	}
	// Create .txt file containing reference to the original file
	txtFile := strings.TrimSuffix(path, ".p12") + ".txt"
	if err = os.WriteFile(txtFile, fmt.Appendf(*new([]byte), placeholderPrefix, path), 0644); err != nil {
		return fmt.Errorf("Error creating placeholder file: %v", err)
	}

	return nil
}

// HandleText processes text files with sensitive data
func (m *Masker) HandleText(buf []byte, findings ...finding) error {
	// Convert buffer to string
	lines := strings.Split(string(buf), "\n")

	// Process chunks in parallel
	numWorkers := runtime.NumCPU()
	workChan := make(chan chunk, len(findings))
	resultChan := make(chan result, len(findings))

	// Create chunks
	for _, f := range findings {
		// Get lines for this chunk (adjusting for 0-based index)
		start, end := f.StartLine, f.EndLine

		workChan <- chunk{
			startLine: start - 1,
			endLine:   end - 1,
			match:     f.Match,
			content:   lines[start-1 : end],
		}
	}
	close(workChan)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for c := range workChan {
				sourceStr := strings.Join(c.content, "\n")
				targetStr := strings.NewReplacer(c.match, placeholderMask).Replace(sourceStr)

				resultChan <- result{
					startLine: c.startLine,
					endLine:   c.endLine,
					content:   strings.Split(targetStr, "\n"),
				}
			}
		}()
	}

	// Close result channel when all workers are done
	wg.Wait()
	close(resultChan)

	// Collect results and update lines
	for r := range resultChan {
		lines = append(lines[:r.startLine], append(r.content, lines[r.endLine:]...)...)
	}

	// Recreate file with updated lines
	if err := m.RecreateFile(findings[0].File, lines...); err != nil {
		return fmt.Errorf("Error recreating file: %v", err)
	}

	return nil
}

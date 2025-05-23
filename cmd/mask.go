package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/google/uuid"
)

const placeholderPrefix = "This file was deleted because it matched the pkcs12-file rule. Original file: %s"

// Masker handles the masking of sensitive data in files
type Masker struct {
	logger          *Logger
	findings        map[string][]finding // Map of file path to findings
	sourceDir       string
	targetDir       string
	placeholderMask string
	newLineSequence string
}

// NewMasker creates a new Masker with the given logger
func NewMasker(sourceDir string, targetDir string, findings []finding, placeholderMask string, newLineSequence string, logger *Logger) *Masker {
	// Group findings by file
	fileFindings := make(map[string][]finding)
	for _, f := range findings {
		// replace source and target directory
		f.ID = uuid.New().String()
		path := strings.NewReplacer(sourceDir, targetDir).Replace(f.File)
		fileFindings[path] = append(fileFindings[path], f)
	}

	return &Masker{
		logger:          logger,
		findings:        fileFindings,
		sourceDir:       sourceDir,
		targetDir:       targetDir,
		placeholderMask: placeholderMask,
		newLineSequence: newLineSequence,
	}
}

// Process processes all findings across files
func (m *Masker) Process() map[string][]finding {
	return m.ProcessWithContext(context.Background())
}

// ProcessWithContext processes all findings across files with context support
func (m *Masker) ProcessWithContext(ctx context.Context) map[string][]finding {
	// Create a semaphore to limit concurrency
	maxWorkers := runtime.NumCPU()
	sem := make(chan struct{}, maxWorkers)

	// Create a wait group to wait for all goroutines
	var wg sync.WaitGroup

	// Process each file
	j := 1
	N := len(m.findings)
	for path, fileFinding := range m.findings {
		// Check if context is canceled
		select {
		case <-ctx.Done():
			return m.findings
		default:
			// Continue processing
		}

		// Acquire semaphore slot
		sem <- struct{}{}

		wg.Add(1)
		go func(path string, fileFinding []finding, i int) {
			// Release semaphore slot and mark as done when finished
			defer func() {
				<-sem
				wg.Done()
			}()

			m.logger.Info("[%d/%d] Checking findings in %s", i, N, path)

			// Check if any findings
			if len(fileFinding) == 0 {
				m.logger.Success("[%d/%d] Nothing to do. File has no findings.", i, N, path)
				return
			}

			// Get appropriate file handler
			handler, err := m.ParseFileType(path, fileFinding)
			if err != nil {
				m.logger.Error("[%d/%d] Error parsing type of file: %v", i, N, err)
				return
			}
			if handler == nil {
				m.logger.Success("[%d/%d] Nothing to do. File is empty.", i, N, path)
				return
			}

			// Handle file
			err = handler()
			if err != nil {
				m.logger.Error("[%d/%d] Error handling file: %v", i, N, err)
				return
			}

			m.logger.Success("[%d/%d] Handled %d finding(s)", i, N, len(fileFinding))
		}(path, fileFinding, j)

		// Increment file index
		j++
	}

	// Set up done channel for waiting with context support
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for all goroutines to complete or context to be canceled
	select {
	case <-done:
		// All processing completed
	case <-ctx.Done():
		m.logger.Warning("Processing interrupted: %v", ctx.Err())
	}

	return m.findings
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
		return m.HandleText(buf, path, fileFinding...)
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
		content := strings.Join(lines, m.newLineSequence)
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
	if err = os.WriteFile(txtFile, fmt.Appendf(*new([]byte), placeholderPrefix, path), 0600); err != nil {
		return fmt.Errorf("Error creating placeholder file: %v", err)
	}

	return nil
}

// HandleText processes text files with sensitive data
func (m *Masker) HandleText(buf []byte, path string, findings ...finding) error {
	// Join all lines to create a single text buffer
	fullText := string(buf)

	// Clean up the filename for variable naming
	maskPrefix := cleanFileName(path)

	// Process each finding sequentially
	for _, f := range findings {
		// Replace the match with our placeholder
		placeholder := fmt.Sprintf(m.placeholderMask, maskPrefix, f.RuleID, f.ID)
		fullText = strings.Replace(fullText, f.Secret, placeholder, -1)
	}

	// Split text back into lines
	updatedLines := strings.Split(fullText, m.newLineSequence)

	// Recreate file with updated lines
	if err := m.RecreateFile(path, updatedLines...); err != nil {
		return fmt.Errorf("error recreating file: %v", err)
	}

	return nil
}

func cleanFileName(path string) string {
	// Get filename without extension for variable name
	fileName := filepath.Base(path)
	fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName))

	// Clean up the filename for variable naming
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, fileName)
}

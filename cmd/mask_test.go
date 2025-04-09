package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMasker_HandleText(t *testing.T) {
	// Setup test environment
	tmpDir := os.TempDir()

	// Create a test file with sensitive data
	testFilePath := filepath.Join(tmpDir, "test.txt")
	sensitiveContent := "username=admin\npassword=secret123\napi_key=abcdef123456"

	if err := os.WriteFile(testFilePath, []byte(sensitiveContent), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create a logger for testing - use the correct constructor
	logger := Default()

	// Create findings for the sensitive data with correct finding struct
	findings := []finding{
		{
			RuleID:      "password",
			StartLine:   2,
			EndLine:     2,
			Match:       "password=secret123",
			Secret:      "secret123",
			File:        testFilePath,
			Entropy:     3.5,
			Fingerprint: "password-1",
			ID:          "test-id-1", // Add fixed ID for testing
		},
		{
			RuleID:      "api_key",
			StartLine:   3,
			EndLine:     3,
			Match:       "api_key=abcdef123456",
			Secret:      "abcdef123456",
			File:        testFilePath,
			Entropy:     2.8,
			Fingerprint: "api-key-1",
			ID:          "test-id-2", // Add fixed ID for testing
		},
	}

	// Initialize the masker
	masker := NewMasker(tmpDir, tmpDir, findings, "{{masked_%s__%s}}", "\n", logger)

	// Test text file handling
	buf, _ := os.ReadFile(testFilePath)
	if err := masker.HandleText(buf, testFilePath, findings...); err != nil {
		t.Fatalf("HandleText failed: %v", err)
	}

	// Read the modified file
	modifiedContent, err := os.ReadFile(testFilePath)
	if err != nil {
		t.Fatalf("Failed to read modified file: %v", err)
	}

	// Verify masked content with the new UUID pattern
	expected := "username=admin\n{{masked_test__password__test-id-1}}\n{{masked_test__api_key__test-id-2}}"
	if string(modifiedContent) != expected {
		t.Errorf("Expected content to be\n%s\nbut got\n%s", expected, string(modifiedContent))
	}
}

func TestMasker_HandleBinary(t *testing.T) {
	// Setup test environment
	tmpDir := os.TempDir()

	// Create a test binary file
	testFilePath := filepath.Join(tmpDir, "cert.p12")
	binaryContent := []byte{0x01, 0x02, 0x03, 0x04} // Some binary content

	if err := os.WriteFile(testFilePath, binaryContent, 0600); err != nil {
		t.Fatalf("Failed to write test binary file: %v", err)
	}

	// Create a logger for testing - use the correct constructor
	logger := Default()

	// Create findings for the binary file with correct finding struct
	findings := []finding{
		{
			RuleID:      "pkcs12-file",
			StartLine:   0,
			EndLine:     0,
			Match:       "",
			Secret:      "",
			File:        testFilePath,
			Entropy:     0.0,
			Fingerprint: "pkcs12-1",
			ID:          "test-id-3", // Add fixed ID for testing
		},
	}

	// Initialize the masker
	masker := NewMasker(tmpDir, tmpDir, findings, "{{masked_%s_%s}}", "\n", logger)

	// Test binary file handling

	if err := masker.HandleBinary(testFilePath); err != nil {
		t.Fatalf("HandleBinary failed: %v", err)
	}

	// Verify original file is empty
	fileInfo, err := os.Stat(testFilePath)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}
	if fileInfo.Size() != 0 {
		t.Errorf("Expected file to be empty, but got size %d", fileInfo.Size())
	}

	// Check for placeholder text file
	txtFilePath := strings.TrimSuffix(testFilePath, ".p12") + ".txt"
	txtContent, err := os.ReadFile(txtFilePath)
	if err != nil {
		t.Fatalf("Failed to read placeholder file: %v", err)
	}

	expectedPrefix := "This file was deleted because it matched the pkcs12-file rule"
	if !strings.Contains(string(txtContent), expectedPrefix) {
		t.Errorf("Expected placeholder file to contain %q, but got %q", expectedPrefix, string(txtContent))
	}
}

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMasker_HandleText(t *testing.T) {
	// Create temp directory for test files
	tempDir, err := os.MkdirTemp("", "masker-text-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test cases
	testCases := []struct {
		name     string
		content  string
		findings []finding
		expected string
	}{
		{
			name:    "Single line mask",
			content: "line1\r\nline2 secret123 line2\r\nline3",
			findings: []finding{
				{
					File:      filepath.Join(tempDir, "test1.txt"),
					Match:     "secret123",
					StartLine: 2,
					EndLine:   2,
				},
			},
			expected: "line1\r\nline2 ***[REDACTED]*** line2\r\nline3",
		},
		{
			name:    "Multi-line mask",
			content: "line1\r\nline2 secret123\r\nline3 secret123 line3\r\nline4",
			findings: []finding{
				{
					File:      filepath.Join(tempDir, "test2.txt"),
					Match:     "secret123",
					StartLine: 2,
					EndLine:   3,
				},
			},
			expected: "line1\r\nline2 ***[REDACTED]***\r\nline3 ***[REDACTED]*** line3\r\nline4",
		},
		{
			name:    "Cross-line boundary mask",
			content: "line1\r\nline2\r\nline3\r\nline4",
			findings: []finding{
				{
					File:      filepath.Join(tempDir, "test3.txt"),
					Match:     "line2\r\nline3",
					StartLine: 2,
					EndLine:   3,
				},
			},
			expected: "line1\r\n***[REDACTED]***\r\nline4",
		},
		{
			name:    "Multiple findings",
			content: "line1 key=abc\r\nline2 password=xyz\r\nline3",
			findings: []finding{
				{
					File:      filepath.Join(tempDir, "test4.txt"),
					Match:     "key=abc",
					StartLine: 1,
					EndLine:   1,
				},
				{
					File:      filepath.Join(tempDir, "test4.txt"),
					Match:     "password=xyz",
					StartLine: 2,
					EndLine:   2,
				},
			},
			expected: "line1 ***[REDACTED]***\r\nline2 ***[REDACTED]***\r\nline3",
		},
		{
			name:    "Empty file",
			content: "",
			findings: []finding{
				{
					File:      filepath.Join(tempDir, "test5.txt"),
					Match:     "secret123",
					StartLine: 1,
					EndLine:   1,
				},
			},
			expected: "",
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create logger
			logger := NewLogger(os.Stdout, LogLevel(0))

			// Create test file
			testFilePath := tc.findings[0].File
			err := os.MkdirAll(filepath.Dir(testFilePath), 0755)
			if err != nil {
				t.Fatalf("Failed to create test dir: %v", err)
			}
			err = os.WriteFile(testFilePath, []byte(tc.content), 0600)
			if err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			// Create masker
			masker := NewMasker("", "", tc.findings, logger)

			// Read file content
			fileContent, err := os.ReadFile(testFilePath)
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Process the file
			err = masker.HandleText(fileContent, testFilePath, tc.findings...)
			if err != nil {
				t.Errorf("HandleText() error = %v", err)
			}

			// Verify result
			resultContent, err := os.ReadFile(testFilePath)
			if err != nil {
				t.Fatalf("Failed to read result file: %v", err)
			}

			if string(resultContent) != tc.expected {
				t.Errorf("Expected content:\n%s\n\nGot:\n%s", tc.expected, string(resultContent))
			}
		})
	}
}

func TestMaskerWithMockJSON(t *testing.T) {
	// Create temp directories for source and target
	sourceDir, err := os.MkdirTemp("", "masker-json-source")
	if err != nil {
		t.Fatalf("Failed to create temp source dir: %v", err)
	}
	defer os.RemoveAll(sourceDir)

	targetDir, err := os.MkdirTemp("", "masker-json-target")
	if err != nil {
		t.Fatalf("Failed to create temp target dir: %v", err)
	}
	defer os.RemoveAll(targetDir)

	// Create test files with credentials
	testFiles := map[string]string{
		"file1.txt": "This is line 1\r\nAPI_KEY=secret1234\r\nThis is line 3",
		"file2.txt": "First line\r\nSecond line with PASSWORD=abc123\r\nThird line",
		"file3.p12": "Binary content simulation", // Will be handled as binary
	}

	// Create the test files in source and target directories
	for name, content := range testFiles {
		filePath := filepath.Join(sourceDir, name)
		targetPath := filepath.Join(targetDir, name)

		// Write to source directory
		err := os.WriteFile(filePath, []byte(content), 0600)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}

		// Copy to target directory
		err = os.MkdirAll(filepath.Dir(targetPath), 0755)
		if err != nil {
			t.Fatalf("Failed to create target directory for %s: %v", name, err)
		}

		err = os.WriteFile(targetPath, []byte(content), 0600)
		if err != nil {
			t.Fatalf("Failed to copy test file to target %s: %v", name, err)
		}
	}

	// Create mock findings
	mockFindings := []finding{
		{
			RuleID:    "api-key",
			File:      filepath.Join(targetDir, "file1.txt"),
			Match:     "secret1234",
			StartLine: 2,
			EndLine:   2,
		},
		{
			RuleID:    "password",
			File:      filepath.Join(targetDir, "file2.txt"),
			Match:     "abc123",
			StartLine: 2,
			EndLine:   2,
		},
		{
			RuleID:    "pkcs12-file",
			File:      filepath.Join(targetDir, "file3.p12"),
			Match:     "",
			StartLine: 0,
			EndLine:   0,
		},
	}

	// Create mock.gitleaks.json
	mockJSONPath := filepath.Join(sourceDir, "mock.gitleaks.json")
	mockJSON, err := json.MarshalIndent(mockFindings, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal mock findings: %v", err)
	}
	err = os.WriteFile(mockJSONPath, mockJSON, 0600)
	if err != nil {
		t.Fatalf("Failed to write mock.gitleaks.json: %v", err)
	}

	// Run the masker
	logger := NewLogger(os.Stdout, LogLevel(0))
	masker := NewMasker(sourceDir, targetDir, mockFindings, logger)
	masker.Process()

	// Verify results
	file1Content, err := os.ReadFile(filepath.Join(targetDir, "file1.txt"))
	if err != nil {
		t.Fatalf("Failed to read processed file1.txt: %v", err)
	}
	if !strings.Contains(string(file1Content), "API_KEY=***[REDACTED]***") {
		t.Errorf("file1.txt was not properly masked: %s", string(file1Content))
	}

	file2Content, err := os.ReadFile(filepath.Join(targetDir, "file2.txt"))
	if err != nil {
		t.Fatalf("Failed to read processed file2.txt: %v", err)
	}
	if !strings.Contains(string(file2Content), "PASSWORD=***[REDACTED]***") {
		t.Errorf("file2.txt was not properly masked: %s", string(file2Content))
	}

	// Check binary file handling
	file3Content, err := os.ReadFile(filepath.Join(targetDir, "file3.p12"))
	if err != nil {
		t.Fatalf("Failed to read processed file3.p12: %v", err)
	}
	if len(file3Content) > 0 {
		t.Errorf("file3.p12 should be empty, got content of length %d", len(file3Content))
	}

	txtFile := filepath.Join(targetDir, "file3.txt")
	if _, err := os.Stat(txtFile); os.IsNotExist(err) {
		t.Error("Placeholder text file was not created for binary file")
	}
}

func TestMultilineCredentialMasking(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "credential-multiline-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test file with multiline credentials
	testFilePath := filepath.Join(tempDir, "multiline.txt")
	multilineContent := "Line 1\r\n-----BEGIN PRIVATE KEY-----\r\nABCDEF1234567890\r\n-----END PRIVATE KEY-----\r\nLine 5"

	err = os.WriteFile(testFilePath, []byte(multilineContent), 0600)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create a finding
	testFinding := finding{
		RuleID:    "private-key",
		File:      testFilePath,
		Match:     "-----BEGIN PRIVATE KEY-----\r\nABCDEF1234567890\r\n-----END PRIVATE KEY-----",
		StartLine: 2,
		EndLine:   4,
	}

	// Create a masker and process the file
	logger := NewLogger(os.Stdout, LogLevel(0))
	masker := NewMasker("", "", []finding{testFinding}, logger)

	// Read file content
	fileContent, err := os.ReadFile(testFilePath)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	// Process the file
	err = masker.HandleText(fileContent, testFilePath, testFinding)
	if err != nil {
		t.Fatalf("HandleText failed: %v", err)
	}

	// Read the processed file
	processedContent, err := os.ReadFile(testFilePath)
	if err != nil {
		t.Fatalf("Failed to read processed file: %v", err)
	}

	// Check that the credential was properly masked
	if strings.Contains(string(processedContent), "BEGIN PRIVATE KEY") {
		t.Error("Multiline credential was not properly masked")
	}

	if !strings.Contains(string(processedContent), placeholderMask) {
		t.Error("Placeholder mask not found in processed file")
	}

	expected := "Line 1\r\n***[REDACTED]***\r\nLine 5"
	if string(processedContent) != expected {
		t.Errorf("Expected:\n%s\n\nGot:\n%s", expected, string(processedContent))
	}
}

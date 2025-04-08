# Credential Masker

A tool for masking sensitive credentials and other confidential information found in code repositories.

## Overview

Credential Masker is designed to process files containing sensitive credentials and redact them for secure storage or sharing. It works by taking Gitleaks JSON reports of secrets found in a repository, then creating a sanitized copy of the repository with all credentials masked.

## Features

- Processes Gitleaks report files to identify secrets in repositories
- Creates sanitized copies of repositories with masked credentials
- Handles both text and binary files with appropriate masking strategies
- Supports concurrent processing for better performance
- Graceful cancellation via context and signal handling
- Comprehensive logging with configurable log levels

## Installation

### From releases

Download the appropriate binary for your platform from the [Releases](https://github.com/yungjakey/credential-masker/releases) page.

You can also use the following commands to download a specific release:

```bash
# For Linux (amd64)
curl -L https://github.com/yungjakey/credential-masker/releases/download/v1.0.0/credential-masker-linux-amd64 -o credential-masker
chmod +x credential-masker

# For Linux (arm64)
curl -L https://github.com/yungjakey/credential-masker/releases/download/v1.0.0/credential-masker-linux-arm64 -o credential-masker
chmod +x credential-masker

# For macOS (amd64)
curl -L https://github.com/yungjakey/credential-masker/releases/download/v1.0.0/credential-masker-darwin-amd64 -o credential-masker
chmod +x credential-masker

# For macOS (arm64)
curl -L https://github.com/yungjakey/credential-masker/releases/download/v1.0.0/credential-masker-darwin-arm64 -o credential-masker
chmod +x credential-masker

# For Windows
curl -L https://github.com/yungjakey/credential-masker/releases/download/v1.0.0/credential-masker-windows-amd64.exe -o credential-masker.exe
```

Replace `v1.0.0` with the specific version you want to download.

### From source

```bash
# Clone the repository
git clone https://github.com/yungjakey/credential-masker.git
cd credential-masker

# Build the binary
go build -o bin/credential-masker ./cmd
```

### Using Docker

```bash
# Pull the image from GitHub Container Registry
docker pull ghcr.io/yungjakey/credential-masker:latest

# Or build locally
docker build -t credential-masker .
```

## Usage

```bash
credential-masker --findings path/to/gitleaks.json --source path/to/source/repo --target path/to/target/repo
```

### Command-line options

- `--findings`: Path to Gitleaks findings JSON file (default: "reports/arcon_formulare.gitleaks.json")
- `--source`: Path to source repository (default: "external/source/arcon_formulare")
- `--target`: Path to target repository for masked files (default: "external/target/arcon_formulare")
- `--log-level`: Log level (DEBUG, INFO, SUCCESS, WARNING, ERROR, FATAL) (default: "INFO")

### Examples

Basic usage:
```bash
credential-masker --findings reports/repo.gitleaks.json --source ./source-repo --target ./masked-repo
```

With Docker:
```bash
docker run -v $(pwd):/data ghcr.io/yungjakey/credential-masker:latest \
  --findings /data/reports/repo.gitleaks.json \
  --source /data/source-repo \
  --target /data/masked-repo
```

## Code Structure

The tool consists of several Go modules in the `cmd` directory:

### Main Components

- **main.go**: Application entry point that handles CLI arguments, sets up signal handling, and coordinates the credential masking process.
- **mask.go**: Contains the `Masker` type which handles the core functionality of processing and masking credentials in files.
- **config.go**: Handles CLI flag parsing and configuration validation.
- **logger.go**: Provides a flexible logging system with multiple severity levels.

### Key Types and Functions

- `finding`: Represents a secret found by Gitleaks, including its location and the matched content.
- `Masker`: The core component that processes findings and applies masking.
  - `Process()`: Processes all findings across files.
  - `ProcessWithContext()`: Processes with context support for cancellation.
  - `HandleText()`: Processes text files with sensitive data.
  - `HandleBinary()`: Processes binary files with sensitive data.

### Processing Flow

1. Load Gitleaks findings from JSON file
2. Copy source repository to target directory (if not already existing)
3. Group findings by file for efficient processing
4. Process each file concurrently:
   - Determine if file is text or binary
   - Apply appropriate masking strategy:
     - For text files: Replace sensitive strings with redaction placeholders
     - For binary files: Replace with placeholder text files
5. Save processed findings back to a grouped JSON file

## GitHub Workflows

The repository includes two GitHub workflow configurations:

### Build and Publish Workflow

Located at `.github/workflows/build-and-publish.yml`, this workflow:

- Triggers on pushes to the main branch, tag pushes with format `v*`, and pull requests to main
- Builds Docker images for multiple platforms (Linux amd64/arm64, Windows amd64)
- Publishes built images to GitHub Container Registry (except for pull requests)
- Tags images based on Git tags, branches, and commit SHAs

### Create Release Workflow

Located at `.github/workflows/create-release.yml`, this workflow:

- Triggers when a tag with the format `v*` is pushed
- Builds binaries for multiple platforms (Linux amd64/arm64, Windows amd64)
- Creates a GitHub release with the built binaries attached
- Generates release notes automatically

## Docker Support

The repository includes a Dockerfile for containerization:

- Uses a multi-stage build process for smaller images
- First stage builds the Go binary with configurable platform targets
- Second stage creates a minimal Alpine-based runtime image
- Accepts build arguments:
  - `GOOS`: Target operating system (default: linux)
  - `GOARCH`: Target architecture (default: amd64)
  - `BINARY_NAME`: Name of the built binary (default: credential-masker)

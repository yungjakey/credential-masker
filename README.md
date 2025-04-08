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
go build -o dist/credential-masker ./cmd
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

### Verify PR Workflow

Located at `.github/workflows/verify-pr.yml`, this workflow:

- Triggers on pull requests to the main branch
- Verifies Go modules are correctly configured
- Runs tests to ensure code quality
- Checks that the project builds successfully

### Create Release Workflow

Located at `.github/workflows/create-release.yml`, this workflow:

- Triggers when a tag with the format `v*` is pushed (e.g., `v1.0.0`, `v2.3.1`)
- Builds binaries for multiple platforms (Linux amd64/arm64, macOS amd64/arm64, Windows amd64)
- Creates a GitHub release with the built binaries attached
- Generates release notes automatically

The workflow builds each binary with version information embedded and uploads them as separate artifacts, then combines them in the release. If you encounter issues with empty tags or incorrect file paths, ensure:

1. You're pushing a tag that starts with 'v'
2. The tag is properly formatted (e.g., `v1.0.0`)
3. The GitHub token has appropriate permissions to create releases

The release will appear in the GitHub Releases section with downloadable binaries for each platform.

## Docker Support

The repository includes a Dockerfile for containerization:

- Uses a multi-stage build process for smaller images
- First stage builds the Go binary with configurable platform targets
- Second stage creates a minimal Alpine-based runtime image
- Accepts build arguments:
  - `GOOS`: Target operating system (default: linux)
  - `GOARCH`: Target architecture (default: amd64)
  - `BINARY_NAME`: Name of the built binary (default: credential-masker)

## Local Building and Releases

The repository includes a local build script that can be used to build the project for multiple platforms and optionally create GitHub releases.

### Using the Local Build Script

The `build-local.sh` script allows you to:

- Build the project for multiple platforms (Linux, macOS, Windows) in parallel
- Optionally create and publish a GitHub release with the built binaries

```bash
# Build for all platforms
./build-local.sh

# Build and publish a release with auto-detected version
./build-local.sh --publish

# Build and publish a release with a specific version tag
./build-local.sh --publish --version v1.0.0
```

### Triggering a Release

You can trigger a release in two ways:

1. **Local Release**: Run the build script with the `--publish` flag as shown above.

2. **GitHub Actions Release**: Push a tag with the format `v*` (e.g., `v1.0.0`) to the repository:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
   This will automatically trigger the GitHub Actions workflow to build and publish a release.

## Troubleshooting

If you encounter issues during the build or release process, please refer to the [Troubleshooting Guide](docs/troubleshooting.md) for common solutions.

## Development

### Pre-commit Hooks

This project uses pre-commit hooks to ensure code quality. To set up:

1. Install pre-commit: `pip install pre-commit`
2. Set up the git hooks: `pre-commit install`
3. Make sure the build script is executable: `chmod +x build-local.sh`

The pre-commit setup includes:
- Code formatting (go fmt, go imports)
- Linting (golangci-lint)
- Shell script checking (shellcheck)
- GitHub Actions workflow validation (actionlint)
- Go tests and build verification
- YAML and other file validations

Now, the pre-commit hooks will run automatically before each commit, ensuring:
- Code is properly formatted
- Tests pass
- Build succeeds
- Shell scripts are valid
- GitHub Actions workflows are valid

You can manually run all pre-commit hooks with:
```
pre-commit run --all-files
```

To build for all platforms during pre-commit (optional):
```
BUILD_ALL_PLATFORMS=true pre-commit run go-build
```

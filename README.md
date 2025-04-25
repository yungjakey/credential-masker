# Credential Masker

A tool to mask credentials in logs and output.

## CI/CD Workflows

This project uses GitHub Actions for continuous integration and deployment. Here's an overview of the available workflows:

### Pull Request Verification

When you create a pull request targeting the `main` branch, the `Verify PR` workflow automatically runs to ensure code quality:

- Code linting with golangci-lint
- Unit tests with coverage reporting
- Build verification

### Automated Releases with release-please

The project uses [release-please](https://github.com/googleapis/release-please) for automated versioning and changelog generation:

1. When commits are pushed to the `main` branch, release-please:
   - Analyzes commit messages (using [Conventional Commits](https://www.conventionalcommits.org/))
   - Creates or updates a release PR when appropriate
   - Generates a changelog based on commit messages
   - Updates version information

2. When the release PR is merged, release-please:
   - Creates a new GitHub release
   - Tags the repository with the new version
   - Publishes the changelog

#### Commit Message Format

For release-please to work properly, format your commit messages following the Conventional Commits standard:

- `feat: add new feature` - Triggers a minor version bump (0.1.0 → 0.2.0)
- `fix: resolve bug` - Triggers a patch version bump (0.1.0 → 0.1.1)
- `docs: update README` - No version bump, but appears in changelog
- `chore: update dependencies` - No version bump, hidden in changelog

Breaking changes should be indicated with an exclamation mark:
- `feat!: change API` or `feat: change API\n\nBREAKING CHANGE: description` - Triggers a major version bump (0.1.0 → 1.0.0)

### Binary Builds and Releases

When a release is created (either automatically by release-please or manually through the GitHub UI), the `Create Release` workflow:

1. Builds binaries for multiple platforms:
   - Linux (amd64, arm64)
   - macOS (amd64, arm64)
   - Windows (amd64)
   - Android (arm64)

2. Attaches these binaries to the GitHub release

### Manual Releases

In case you need to create a release manually:

1. Go to the Actions tab in the GitHub repository
2. Select the "Create Release" workflow
3. Click "Run workflow"
4. Enter a version tag (e.g., `v1.0.0`)
5. Click "Run workflow"

Note: The tag must already exist in the repository or the workflow will fail.

## Development

### Prerequisites

- Go 1.23 or higher

### Building the Project

```bash
go build -o credential-masker ./cmd
```

### Testing

Run tests:

```bash
go test -v ./...
```

Run tests with coverage:

```bash
go test -v -coverprofile=coverage.txt -covermode=atomic ./...
```

### Linting

Make sure your code meets the project's style guidelines:

```bash
golangci-lint run
```

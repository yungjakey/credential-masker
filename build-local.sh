#!/bin/bash

# Process command line arguments
PUBLISH_RELEASE=false
VERSION_TAG="latest"

while [[ "$#" -gt 0 ]]; do
    case $1 in
    --publish) PUBLISH_RELEASE=true ;;
    --version)
        VERSION_TAG="$2"
        shift
        ;;
    *)
        echo "Unknown parameter: $1"
        exit 1
        ;;
    esac
    shift
done

# Check if GNU parallel is installed
if ! command -v parallel &>/dev/null; then
    echo "GNU parallel is not installed. To install:"
    echo "  brew install parallel"
    echo "Running in sequential mode instead..."
    PARALLEL_AVAILABLE=false
else
    PARALLEL_AVAILABLE=true
fi

# Create output directory
mkdir -p dist

# Define build configurations
declare -a configs=(
    "linux amd64 dist/credential-masker-linux-amd64"
    "linux arm64 dist/credential-masker-linux-arm64"
    "darwin amd64 dist/credential-masker-darwin-amd64"
    "darwin arm64 dist/credential-masker-darwin-arm64"
    "windows amd64 dist/credential-masker-windows-amd64.exe"
)

# Build function for a single platform
build_platform() {
    local os=$1
    local arch=$2
    local output=$3

    echo "Building ${os}/${arch}..."
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -o $output ./cmd
    echo "✓ Built ${output}"
}

# Export function to make it available to parallel
export -f build_platform

if [ "$PARALLEL_AVAILABLE" = true ]; then
    # Run builds in parallel
    echo "Building all platforms in parallel..."
    printf '%s\n' "${configs[@]}" | parallel --colsep ' ' build_platform {1} {2} {3}
else
    # Run builds sequentially if parallel is not available
    for config in "${configs[@]}"; do
        read -r os arch output <<<"$config"
        build_platform "$os" "$arch" "$output"
    done
fi

echo "Build completed! Binaries available in dist/ directory"

# Optional: display summary of built files
echo -e "\nBuilt binaries:"
ls -lh dist/

# Publish to GitHub Releases if requested
if [ "$PUBLISH_RELEASE" = true ]; then
    echo -e "\nPreparing to publish to GitHub Releases..."

    # Check for required tools
    if ! command -v gh &>/dev/null; then
        echo "GitHub CLI (gh) is not installed. Please install it first:"
        echo "  brew install gh"
        exit 1
    fi

    # Set version tag if not provided
    if [ -z "$VERSION_TAG" ]; then
        VERSION_TAG=$(git describe --tags --always 2>/dev/null || echo "latest")
        echo "No version specified, using: $VERSION_TAG"
    fi

    # Make sure we're authenticated with GitHub
    if ! gh auth status &>/dev/null; then
        echo "Not authenticated with GitHub. Please run 'gh auth login' first."
        exit 1
    fi

    # Create a GitHub release
    echo "Creating GitHub release for tag $VERSION_TAG..."

    # Check if the tag exists, create it if not
    if ! git rev-parse "$VERSION_TAG" >/dev/null 2>&1; then
        echo "Tag $VERSION_TAG doesn't exist, creating it..."
        git tag "$VERSION_TAG"
        git push origin "$VERSION_TAG"
    fi

    # Create release and upload binaries
    echo "Creating release and uploading binaries..."
    gh release create "$VERSION_TAG" \
        --title "Release $VERSION_TAG" \
        --generate-notes \
        dist/credential-masker-linux-amd64 \
        dist/credential-masker-linux-arm64 \
        dist/credential-masker-darwin-amd64 \
        dist/credential-masker-darwin-arm64 \
        dist/credential-masker-windows-amd64.exe

    echo "✓ Successfully published release $VERSION_TAG with binaries"
fi

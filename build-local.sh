#!/bin/bash

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

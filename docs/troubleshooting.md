# Troubleshooting Release Issues

This document covers common issues encountered during the build and release process for Credential Masker.

## GitHub Actions Build Failures

### Go Module Download Errors

**Error:**
```
buildx failed with: ERROR: failed to solve: process "/bin/sh -c go mod download" did not complete successfully: exit code: 1
```

**Solutions:**
1. Check if `go.mod` and `go.sum` files are properly committed to the repository
2. Make sure all dependencies are accessible (no private repositories without authentication)
3. Try to run `go mod tidy` locally before pushing
4. Ensure your Go version in workflows matches the one used in development

### Platform Matching Issues

**Error:**
```
buildx failed with: ERROR: failed to solve: alpine:latest: failed to resolve source metadata for docker.io/library/alpine:latest: no match for platform in manifest: not found
```

**Solutions:**
1. Specify the exact Alpine version instead of `alpine:latest` (e.g., `alpine:3.17`)
2. Explicitly define platform in your Dockerfile or workflow:
   ```yaml
   - name: Set up Docker Buildx
     uses: docker/setup-buildx-action@v2
     with:
       platforms: linux/amd64,linux/arm64,windows/amd64
   ```
3. Check if you're trying to build for platforms not supported by the base image

### Workflow Cancellation Due to Previous Failures

**Error:**
```
The strategy configuration was canceled because "build.linux_amd64" failed
The operation was canceled.
```

**Solutions:**
1. Fix the root cause (usually the first failing job)
2. You can set `fail-fast: false` in your strategy to prevent cancellation of all jobs when one fails:
   ```yaml
   strategy:
     fail-fast: false
     matrix:
       platform: [linux_amd64, linux_arm64, windows_amd64]
   ```

## Cross-Compilation Issues

### Windows Builds Failing

When building for Windows from a non-Windows environment:

1. Ensure CGO is disabled for Windows builds: `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build`
2. Check for platform-specific code that might not compile on Windows
3. Use path separators that work cross-platform (`filepath.Join` instead of hardcoded slashes)

### ARM64 Architecture Issues

For ARM64 builds:

1. Make sure all dependencies support ARM64
2. Test on ARM64 hardware or emulation before releases
3. Use compatible build flags: `GOOS=linux GOARCH=arm64 go build`

## Docker Multi-Platform Builds

For successful multi-platform Docker builds:

1. Use BuildKit for multi-platform support
2. Register QEMU emulators for cross-platform builds:
   ```yaml
   - name: Set up QEMU
     uses: docker/setup-qemu-action@v2
   ```
3. Ensure base images support all target platforms
4. Use a compatible builder instance:
   ```yaml
   - name: Set up Docker Buildx
     uses: docker/setup-buildx-action@v2
   ```

## Local Verification Steps

Before creating a release tag, verify the build process locally:

1. Test cross-compilation:
   ```bash
   # For Linux
   GOOS=linux GOARCH=amd64 go build -o bin/credential-masker-linux-amd64 ./cmd
   
   # For Windows
   GOOS=windows GOARCH=amd64 go build -o bin/credential-masker-windows-amd64.exe ./cmd
   
   # For macOS
   GOOS=darwin GOARCH=amd64 go build -o bin/credential-masker-darwin-amd64 ./cmd
   
   # For ARM64
   GOOS=linux GOARCH=arm64 go build -o bin/credential-masker-linux-arm64 ./cmd
   ```

2. Test Docker build for multi-platform:
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64 -t test-credential-masker .
   ```

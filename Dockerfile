# Simple single-stage build for Linux platforms
FROM golang:1.20-alpine3.17 AS builder

ARG GOOS=linux
ARG GOARCH=amd64

WORKDIR /app

# Copy Go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -o /app/credential-masker ./cmd

# Use a minimal Alpine image for the final container
FROM alpine:3.17

WORKDIR /app
COPY --from=builder /app/credential-masker /app/credential-masker

# Create a non-root user for security
RUN adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["/app/credential-masker"]

# Build stage
FROM golang:1.20-alpine AS builder

WORKDIR /app

# Define build arguments with defaults
ARG GOOS=linux
ARG GOARCH=amd64
ARG BINARY_NAME=credential-masker

# Copy go mod and sum files
COPY go.mod go.sum ./
# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build for the specified platform
RUN go build -o /app/bin/${BINARY_NAME} ./cmd/main.go

# Final stage
FROM alpine:latest

ARG BINARY_NAME=credential-masker
WORKDIR /app

# Copy only the binary from the builder stage
COPY --from=builder /app/bin/${BINARY_NAME} /app/${BINARY_NAME}

# Set execute permissions
RUN chmod +x /app/${BINARY_NAME}

# Default command
ENTRYPOINT ["/app/credential-masker"]

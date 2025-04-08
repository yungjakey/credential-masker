# Build stage
FROM golang:1.20-alpine3.17 AS builder

ARG GOOS=linux
ARG GOARCH=amd64
ARG BINARY_NAME=credential-masker

WORKDIR /app

# Download dependencies first (better caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with specific OS/ARCH target
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -o /app/bin/${BINARY_NAME} ./cmd

# For non-Linux platforms we can stop here - the binary can be extracted from the builder
FROM scratch AS export-stage
COPY --from=builder /app/bin /

# For Linux platforms, create a runnable container
FROM alpine:3.17 AS run-stage

ARG BINARY_NAME=credential-masker
WORKDIR /app

COPY --from=builder /app/bin/${BINARY_NAME} /app/credential-masker

# Create a non-root user
RUN adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["/app/credential-masker"]

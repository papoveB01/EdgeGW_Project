# Stage 1: Build the binary
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install git (required for some Go modules)
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod ./

# Copy source code
COPY . .

# Download dependencies (if any) and build
RUN go mod download || true

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o edge-gateway .

# Stage 2: Hardened Runtime
FROM gcr.io/distroless/static-debian11:nonroot

# Copy the binary and static assets from builder
COPY --from=builder /app/edge-gateway /edge-gateway
COPY --from=builder /app/static /static

WORKDIR /

# Use nonroot user (already set in distroless image)
USER nonroot:nonroot

ENTRYPOINT ["/edge-gateway"]


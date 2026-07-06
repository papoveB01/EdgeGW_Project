# ── Build stage ──────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o edge-gateway ./cmd/gateway
RUN mkdir -p /spool

# ── Runtime stage (distroless, no shell, nonroot) ────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/edge-gateway /edge-gateway
# Writable spool dir for the durable signal queue (nonroot uid 65532)
COPY --from=builder --chown=65532:65532 /spool /spool

EXPOSE 8080

ENTRYPOINT ["/edge-gateway"]

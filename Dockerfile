FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build scanner binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o scanner ./cmd/scanner

# Build Go tools (puredns, subfinder)
RUN GOBIN=/app/tools go install github.com/d3mondev/puredns/v2@latest 2>/dev/null || true
RUN GOBIN=/app/tools go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true

# Build massdns from source
RUN apk add --no-cache git gcc musl-dev make && \
    git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    cd /tmp/massdns && make -j$(nproc) && cp bin/massdns /app/tools/massdns || true

FROM kalilinux/kali-rolling

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    ca-certificates \
    dnsutils \
    whois \
    whatweb \
    amass \
    recon-ng \
    wpscan \
    seclists \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy scanner binary and tools
COPY --from=builder /app/scanner .
COPY --from=builder /app/web ./web
COPY --from=builder /app/tools ./tools

# Create data directories
RUN mkdir -p data

# Resolvers list
COPY data/resolvers.txt data/resolvers.txt

EXPOSE 9090

# The app serves HTTPS by default (self-signed), so probe with -k over https.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD curl -kf https://localhost:9090/login || exit 1

CMD ["./scanner"]

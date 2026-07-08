#!/usr/bin/env bash
#
# Build script for tcpcap.
#
# Usage:
#   ./build.sh              # build windows + linux
#   ./build.sh windows      # build windows only
#   ./build.sh linux        # build linux only (requires Docker daemon running)
#
# The linux build produces a fully static binary that runs on any Linux
# x86_64 without requiring libpcap on the target machine.
#
# Override the Docker registry mirror via MIRROR (default: docker.m.daocloud.io):
#   MIRROR=dockerproxy.com ./build.sh linux

set -euo pipefail

cd "$(dirname "$0")"
# Windows-style path for the Docker volume mount (Git Bash on Windows)
HOST_PATH="$(pwd -W 2>/dev/null || pwd)"

MIRROR="${MIRROR:-docker.m.daocloud.io}"
TARGET="${1:-all}"

build_windows() {
  echo "==> Building windows/amd64..."
  CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags '-s -w' -o tcpcap-windows-amd64.exe .
  echo "    done: tcpcap-windows-amd64.exe"
}

build_linux() {
  echo "==> Building linux/amd64 (static, via Docker)..."
  echo "    (requires the Docker daemon to be running; if it hangs, press Ctrl+C)"
  MSYS_NO_PATHCONV=1 docker run --rm -v "${HOST_PATH}:/src" -w /src \
    "${MIRROR}/library/golang:1.24-alpine" sh -c '
      set -e
      apk add --no-cache git gcc musl-dev libpcap-dev >/dev/null
      CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags "-s -w -linkmode external -extldflags=-static" \
        -o tcpcap-linux-amd64 .
    '
  echo "    done: tcpcap-linux-amd64 (static)"
}

case "$TARGET" in
  windows) build_windows ;;
  linux)   build_linux ;;
  all)     build_windows; build_linux ;;
  *) echo "Unknown target: $TARGET (use: windows | linux | all)"; exit 1 ;;
esac

echo ""
echo "Artifacts:"
ls -la tcpcap-windows-amd64.exe tcpcap-linux-amd64 2>/dev/null || true

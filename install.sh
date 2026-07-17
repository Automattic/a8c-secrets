#!/bin/bash

# Description:
#   Installation script for `a8c-secrets` (https://github.com/Automattic/a8c-secrets)
#
#   The script downloads the `a8c-secrets` binary from GitHub releases for the current platform and architecture
#   and installs it on the system.
#
# The script supports macOS (Intel and ARM), Linux (x86_64), and Windows (x86_64).
#
# Usage:
#   To install a8c-secrets, run:
#     curl -fsSL https://raw.githubusercontent.com/Automattic/a8c-secrets/main/install.sh | bash
#
#   To install to a custom directory:
#     curl -fsSL https://raw.githubusercontent.com/Automattic/a8c-secrets/main/install.sh | bash -s -- --prefix /custom/path
#
#   Or download and run manually:
#     curl -fsSL https://raw.githubusercontent.com/Automattic/a8c-secrets/main/install.sh -o install.sh
#     bash install.sh [--prefix /custom/path]
#

set -euo pipefail

# Parse command line arguments
CUSTOM_PREFIX=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --prefix)
            CUSTOM_PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            CUSTOM_PREFIX="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--prefix /custom/path]" >&2
            exit 1
            ;;
    esac
done

# Determine platform-specific variables
OS=$(uname -s)
ARCH=$(uname -m)

if [[ "$OS" == "MINGW"* ]] || [[ "$OS" == "MSYS"* ]] || [[ "$OS" == "CYGWIN"* ]]; then
    EXECUTABLE_NAME="a8c-secrets.exe"
    INSTALL_CMD="/usr/bin/install"
    IS_WINDOWS=true
else
    EXECUTABLE_NAME="a8c-secrets"
    INSTALL_CMD="install"
    IS_WINDOWS=false
fi

# Map platform and architecture to Rust target triple format
case "$OS" in
    Darwin)
        case "$ARCH" in
            arm64)
                TARGET_TRIPLE="aarch64-apple-darwin"
                ;;
            x86_64)
                TARGET_TRIPLE="x86_64-apple-darwin"
                ;;
            *)
                echo "Unsupported architecture on macOS: $ARCH" >&2
                exit 2
                ;;
        esac
        ;;
    Linux)
        case "$ARCH" in
            x86_64)
                TARGET_TRIPLE="x86_64-unknown-linux-gnu"
                ;;
            aarch64|arm64)
                TARGET_TRIPLE="aarch64-unknown-linux-gnu"
                ;;
            *)
                echo "Unsupported architecture on Linux: $ARCH" >&2
                exit 2
                ;;
        esac
        ;;
    MINGW*|MSYS*|CYGWIN*)
        case "$ARCH" in
            x86_64)
                TARGET_TRIPLE="x86_64-pc-windows-gnu"
                ;;
            *)
                echo "Unsupported architecture on Windows: $ARCH" >&2
                exit 2
                ;;
        esac
        ;;
    *)
        echo "Unsupported operating system: $OS" >&2
        exit 2
        ;;
esac

# Common curl flags used for every request:
#   --location    follow redirects
#   --silent      suppress the progress meter
#   --show-error  still print the reason for a failure (HTTP status or connection error) to stderr, instead of swallowing it
#   --fail        turn an HTTP error response (e.g. 429) into a non-zero exit
CURL_FLAGS=(--location --silent --show-error --fail)

# For GitHub API requests, add an Authorization header when GITHUB_TOKEN is set.
# This raises the API rate limit, helping avoid HTTP 429.
GITHUB_API_CURL_FLAGS=("${CURL_FLAGS[@]}")
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    GITHUB_API_CURL_FLAGS+=(--header "Authorization: Bearer $GITHUB_TOKEN")
fi

# Get the latest release tag from GitHub API.
LATEST_RELEASE_URL="https://api.github.com/repos/Automattic/a8c-secrets/releases/latest"
echo "Fetching latest release information from GitHub..."
if ! RELEASE_INFO=$(curl "${GITHUB_API_CURL_FLAGS[@]}" "$LATEST_RELEASE_URL"); then
    echo "Failed to fetch release information from GitHub" >&2
    exit 1
fi
if [[ -z "$RELEASE_INFO" ]]; then
    echo "Failed to fetch release information from GitHub" >&2
    exit 1
fi

# Extract the version (tag_name) from the release info
VERSION=$(echo "$RELEASE_INFO" | jq -r '.tag_name // empty')
if [[ -z "$VERSION" ]] || [[ "$VERSION" == "null" ]]; then
    echo "Failed to extract version from release information" >&2
    exit 1
fi

# Construct the asset name
if [[ "$IS_WINDOWS" == "true" ]]; then
    ASSET_NAME="a8c-secrets-${TARGET_TRIPLE}-${VERSION}.exe"
else
    ASSET_NAME="a8c-secrets-${TARGET_TRIPLE}-${VERSION}"
fi

# Determine the install directory based on platform
if [[ -n "$CUSTOM_PREFIX" ]]; then
    # Use custom prefix if provided
    INSTALL_DIR="$CUSTOM_PREFIX"
else
    if [[ "$IS_WINDOWS" == "true" ]]; then
        # For Windows, try to use a directory in PATH or user's local bin
        if [[ -n "${LOCALAPPDATA:-}" ]]; then
            INSTALL_DIR="$LOCALAPPDATA/Programs/a8c-secrets"
        else
            INSTALL_DIR="$HOME/.local/bin"
        fi
    else
        # For Unix-like systems, try /usr/local/bin first, fallback to ~/.local/bin
        if [[ -w "/usr/local/bin" ]]; then
            INSTALL_DIR="/usr/local/bin"
        else
            INSTALL_DIR="$HOME/.local/bin"
        fi
    fi
fi

# Create temp directory for download
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Download the binary to temp directory
DOWNLOAD_URL="https://github.com/Automattic/a8c-secrets/releases/download/${VERSION}/${ASSET_NAME}"
TEMP_BINARY="$TEMP_DIR/$EXECUTABLE_NAME"
echo "Downloading $ASSET_NAME from GitHub releases..."
# Note: no Authorization header here on purpose. This URL is github.com (the release asset CDN), not the api.github.com API
if ! curl "${CURL_FLAGS[@]}" --output "$TEMP_BINARY" "$DOWNLOAD_URL"; then
    echo "Failed to download $ASSET_NAME from $DOWNLOAD_URL" >&2
    exit 1
fi


# Install the binary in INSTALL_DIR
INSTALL_PATH="$INSTALL_DIR/$EXECUTABLE_NAME"
echo "Installing $EXECUTABLE_NAME to $INSTALL_PATH..."
"$INSTALL_CMD" -d "$INSTALL_DIR"
"$INSTALL_CMD" -m 755 "$TEMP_BINARY" "$INSTALL_PATH"

# Remove quarantine attribute on macOS
if [[ "$OS" == "Darwin" ]]; then
    if xattr -d com.apple.quarantine "$INSTALL_PATH" 2>/dev/null || true; then
        echo "Removed quarantine attribute from $INSTALL_PATH"
    fi
fi

# Verify installation
if [[ -f "$INSTALL_PATH" ]] && [[ -x "$INSTALL_PATH" ]]; then
    echo "Successfully installed a8c-secrets to $INSTALL_PATH"
    if [[ "$INSTALL_DIR" == "$HOME/.local/bin" ]] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo ""
        echo "Note: $INSTALL_DIR is not in your PATH."
        echo "Add the following to your shell configuration file (~/.bashrc, ~/.zshrc, etc.):"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
else
    echo "Installation failed: $INSTALL_PATH is not executable" >&2
    exit 1
fi

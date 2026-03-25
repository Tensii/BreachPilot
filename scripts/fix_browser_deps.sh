#!/usr/bin/env bash
# Run on the BreachPilot host if browser-check fails with missing library errors.
set -euo pipefail

echo "[*] Installing Chromium runtime dependencies..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    libgbm1 \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libexpat1 \
    libglib2.0-0 \
    libnspr4 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libgtk-3-0 \
    libxshmfence1 \
    libglu1-mesa

echo "[*] Done. Run: breachpilot browser-check"

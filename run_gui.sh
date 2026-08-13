#!/usr/bin/env bash
# 开发态启动 GUI（macOS / Linux）
cd "$(dirname "$0")"
PYTHON="$(command -v python3 || command -v python)"
exec "$PYTHON" jiagu_gui.py

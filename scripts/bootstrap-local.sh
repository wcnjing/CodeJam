#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example."
fi

mkdir -p data workspaces codex-home

echo "Next:"
echo "  1. Fill ARK_API_KEY, ARK_MODEL and APP_PRINCIPALS in .env"
echo "     (APP_PRINCIPALS is required: docker compose runs a production server"
echo "      on 0.0.0.0 and will not start without at least one id:token pair.)"
echo "  2. Run: docker compose up --build"

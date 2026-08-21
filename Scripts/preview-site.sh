#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
published_directory="$repository_root/docs"
preview_directory="$(mktemp -d "$repository_root/.site-preview.XXXXXX")"
port="${PORT:-8000}"

cleanup() {
    rm -rf "$preview_directory"
}
trap cleanup EXIT

if [[ ! -f "$published_directory/index.html" ]]; then
    echo "Build the site before previewing it." >&2
    exit 1
fi

ln -s "$published_directory" "$preview_directory/lockbox-swift"
echo "Previewing at http://localhost:$port/lockbox-swift/"
python3 -m http.server "$port" --directory "$preview_directory"

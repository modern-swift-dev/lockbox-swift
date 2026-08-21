#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
website_directory="$repository_root/Website"
published_directory="$repository_root/docs"
staging_directory="$(mktemp -d "$repository_root/.site-build.XXXXXX")"
site_output_directory="$staging_directory/site"

cleanup() {
    rm -rf "$staging_directory"
}
trap cleanup EXIT

if [[ ! -f "$website_directory/package.json" ]]; then
    echo "Website/package.json is required to build the GitHub Pages site." >&2
    exit 1
fi

npm --prefix "$website_directory" run build -- --outDir "$site_output_directory"

if [[ ! -f "$site_output_directory/index.html" ]]; then
    echo "Astro did not create $site_output_directory/index.html." >&2
    exit 1
fi

bash "$repository_root/Scripts/build-docc.sh" "$site_output_directory/documentation/lockbox"
touch "$site_output_directory/.nojekyll"

node "$repository_root/Scripts/check-site-links.mjs" "$site_output_directory"

rm -rf "$published_directory"
mv "$site_output_directory" "$published_directory"

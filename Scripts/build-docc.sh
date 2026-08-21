#!/usr/bin/env bash

set -euo pipefail

output_directory="${1:?Pass an output directory for generated DocC content.}"
module_name="Lockbox"
hosting_base_path="lockbox-swift/documentation/lockbox"

mkdir -p "$output_directory"

swift package \
    --allow-writing-to-directory "$output_directory" \
    generate-documentation \
    --target "$module_name" \
    --output-path "$output_directory" \
    --transform-for-static-hosting \
    --hosting-base-path "$hosting_base_path"

expected_files=(
    "index.html"
    "data/documentation/lockbox.json"
    "documentation/lockbox/index.html"
    "data/documentation/lockbox/keychainpassword.json"
    "documentation/lockbox/keychainpassword/index.html"
    "data/documentation/lockbox/keychaincriterion.json"
    "documentation/lockbox/keychaincriterion/index.html"
)

for expected_file in "${expected_files[@]}"; do
    if [[ ! -f "$output_directory/$expected_file" ]]; then
        echo "DocC did not create $output_directory/$expected_file." >&2
        exit 1
    fi
done

#!/usr/bin/env bash
set -uo pipefail

FILE="${1:-dist-offline/index.html}"
fail=0
note() { printf '  %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1"; fail=1; }

if [ ! -f "$FILE" ]; then
  echo "FAIL: $FILE does not exist. Run 'npm run build:offline' first."
  exit 1
fi

echo "Checking $FILE ($(wc -c < "$FILE" | tr -d ' ') bytes)"
file_count=$(find "$(dirname "$FILE")" -type f | wc -l | tr -d ' ')
if [ "$file_count" = 1 ]; then note 'output files: 1'; else bad "expected one output file, found $file_count"; fi

# These are the two loose resources in the source document. Both must have
# been replaced by their inline contents in the offline output.
for reference in 'src="./qrllib.js"' 'href="./favicon.ico"'; do
  if grep -a -q -F -- "$reference" "$FILE"; then bad "external resource remains: $reference"; else note "$reference: inlined"; fi
done

if grep -a -q -F 'qrllib v1.2.6' "$FILE"; then note 'application content: present'; else bad 'application content is missing'; fi
if [ "$fail" = 0 ]; then echo 'PASS: offline artefact is self-contained.'; else echo 'FAILED: do not publish this artefact.'; fi
exit "$fail"

#!/usr/bin/env bash
# Validates a Sigma-style detection rule YAML file.
# Exits 2 (blocking) with one message per problem on stdout/stderr.
set -euo pipefail

file="${1:-}"

if [[ -z "$file" || ! -f "$file" ]]; then
  echo "Cannot read rule file: ${file:-<none>}"
  exit 2
fi

errors=()

# description is a required field
if ! grep -qE '^[[:space:]]*description[[:space:]]*:' "$file"; then
  errors+=("Missing required field: description")
fi

# tags must contain at least one MITRE ATT&CK technique (attack.t####)
if ! grep -qiE 'attack\.t[0-9]{3,}' "$file"; then
  errors+=("tags must contain at least one attack.t* entry")
fi

if (( ${#errors[@]} > 0 )); then
  printf '%s\n' "${errors[@]}"
  exit 2
fi

echo "OK: $file"
exit 0

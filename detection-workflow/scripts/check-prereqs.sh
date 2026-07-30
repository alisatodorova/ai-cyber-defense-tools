#!/usr/bin/env bash
# SessionStart hook: warn if required tools are missing.
# Checks for jq and python3. Missing tools -> warning on stderr.
# Always exits 0 so a missing prereq warns without blocking the session.

missing=()

for tool in jq python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  printf "WARNING: missing prerequisite(s): %s. Some hooks/scripts may not work.\n" "${missing[*]}" >&2
fi

exit 0

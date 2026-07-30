#!/usr/bin/env bash
# PreToolUse hook: block tool calls that touch sensitive files.
# Reads the tool-call JSON on stdin. Exit 0 = allow, exit 2 = block.

input=$(cat)

# Extract the target path (empty for tools like Bash that have no file_path).
file=$(printf "%s" "$input" | jq -r '.tool_input.file_path // empty')

# No path to check -> nothing sensitive, allow.
if [ -z "$file" ]; then
  exit 0
fi

# Sensitive path patterns. Matched case-insensitively against the full path.
case "$file" in
  *.env|*/.env|*.env.*) match=1 ;;
  *.key)                match=1 ;;
  *.pem)                match=1 ;;
  */secrets/*|secrets/*)         match=1 ;;
  */credentials/*|credentials/*) match=1 ;;
  *) match=0 ;;
esac

if [ "$match" -eq 1 ]; then
  printf "BLOCKED: '%s' matches a sensitive-file pattern (.env, *.key, *.pem, secrets/, credentials/). Refusing tool call.\n" "$file" >&2
  exit 2
fi

exit 0

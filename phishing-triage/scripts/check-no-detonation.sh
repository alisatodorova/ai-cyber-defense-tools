#!/usr/bin/env bash
# PreToolUse hook: enforce the "never detonate" rule of phishing triage.
#
# Phishing triage is static. Nothing in this project should fetch, resolve, or
# open a URL/attachment pulled from a suspicious email — not via WebFetch, and
# not via a network CLI in Bash (curl/wget/nslookup/…). This hook is a
# harness-enforced backstop for that rule: it holds regardless of what the model
# was told to do, including instructions smuggled inside an email body
# (prompt-injection defense).
#
# Reads the tool-call JSON on stdin. Exit 0 = allow, exit 2 = block.

input=$(cat)

# WebFetch / WebSearch are network-by-definition — block outright. The matcher
# already scoped us to these + Bash, but re-check so the script is correct alone.
tool=$(printf "%s" "$input" | jq -r '.tool_name // empty')
case "$tool" in
  WebFetch|WebSearch)
    printf "BLOCKED: %s performs a network fetch. Phishing triage is static — never resolve or open a URL from a suspicious email. Detonate only in an isolated sandbox, by human decision.\n" "$tool" >&2
    exit 2
    ;;
esac

# For Bash, inspect the command for network utilities that would touch a host.
cmd=$(printf "%s" "$input" | jq -r '.tool_input.command // empty')
if [ -z "$cmd" ]; then
  exit 0
fi

# Case-insensitive match on network-fetch/resolve tooling as a whole word.
lc=$(printf "%s" "$cmd" | tr '[:upper:]' '[:lower:]')
if printf "%s" "$lc" | grep -Eq '(^|[^a-z])(curl|wget|nc|ncat|telnet|nslookup|dig|host|ping|iwr|invoke-webrequest|invoke-restmethod)([^a-z]|$)'; then
  printf "BLOCKED: command appears to make a network request (%s). Phishing triage is static — do not fetch, resolve, or open indicators from a suspicious email. Use a sandbox for dynamic analysis.\n" "$cmd" >&2
  exit 2
fi

exit 0

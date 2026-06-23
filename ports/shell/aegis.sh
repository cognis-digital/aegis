#!/bin/sh
# AEGIS — POSIX shell port of the agent-manifest trifecta auditor.
#
# Mirrors `aegis audit <manifest.json>`: classify each capability along the
# three lethal-trifecta axes (credentials + injection + reach) and report
# agents holding all three (critical) or two of three (high).
#
# Dependency: jq (for JSON parsing). Pure POSIX sh otherwise.
#
#   ./aegis.sh ../../demos/01-basic/agents.json
#   ./aegis.sh --format json manifest.json
#
# Exit: 0 clean · 1 critical/high finding · 2 bad manifest / missing jq.
set -eu

# Signature tokens per axis. The trailing read:*/write:*/etc. entries mirror the
# explicit-scope map from the Python reference so declared scopes count too.
CRED_SIG="secret credential password token api_key apikey private_key privatekey ssh keychain vault env environ dotenv .env oauth access_key aws_ gcp read_file readfile fs.read filesystem file_read database db_query sql private pii customer_data financial billing payment ssn cookie session read:secrets read:files read:db"
INJ_SIG="web fetch http_get browse crawl scrape url email_read read_email inbox mail rss webhook untrusted user_input document pdf parse ingest search rag retrieve comment issue ticket slack_read channel message_read transcribe ocr read:web read:email"
REACH_SIG="send post http_post email_send send_email sendmail sms publish upload write_file writefile fs.write exec shell command subprocess deploy delete transfer payment_send wire purchase order webhook api_call external network dns socket git_push commit create_pr tweet dm call_tool net:outbound write:files exec:shell send:email"
EXEC_TOK="exec shell command subprocess deploy"

format="table"
manifest=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json|--format=json) format="json" ;;
    --format) shift; [ "${1:-}" = "json" ] && format="json" ;;
    --*) ;;
    *) manifest="$1" ;;
  esac
  shift
done

if [ -z "$manifest" ]; then
  echo "usage: aegis.sh [--format json] <manifest.json>" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "aegis: jq is required for the shell port" >&2
  exit 2
fi
if [ ! -f "$manifest" ]; then
  echo "aegis: manifest not found: $manifest" >&2
  exit 2
fi
if ! jq empty "$manifest" >/dev/null 2>&1; then
  echo "aegis: invalid manifest: not valid JSON" >&2
  exit 2
fi

# Normalize manifest shape -> a JSON array of agents.
agents_json=$(jq -c 'if type=="object" and has("agents") then .agents
                     elif type=="array" then .
                     elif type=="object" then [.]
                     else error("manifest must be an object or list") end' "$manifest")

agent_count=$(printf '%s' "$agents_json" | jq 'length')

# Build one normalized search string per axis check.
contains_any() {
  hay="$1"; shift
  for tok in $1; do
    case "$hay" in *"$tok"*) return 0 ;; esac
  done
  return 1
}

findings_out=""
finding_count=0
worst=""
rank() { case "$1" in critical) echo 3 ;; high) echo 2 ;; medium) echo 1 ;; *) echo 0 ;; esac; }
note() {
  sev="$1"; agent="$2"; title="$3"
  finding_count=$((finding_count + 1))
  findings_out="${findings_out}${sev}\t${agent}\t${title}\n"
  if [ -z "$worst" ] || [ "$(rank "$sev")" -gt "$(rank "$worst")" ]; then worst="$sev"; fi
}

i=0
while [ "$i" -lt "$agent_count" ]; do
  agent=$(printf '%s' "$agents_json" | jq -c ".[$i]")
  name=$(printf '%s' "$agent" | jq -r '.name // .id // "unnamed-agent"')

  # Flatten capabilities/tools/permissions into newline-separated normalized strings.
  caps=$(printf '%s' "$agent" | jq -r '
    (.capabilities // .tools // .permissions // [])
    | map(if type=="string" then {name:.} else . end)
    | .[]
    | [(.name // .tool // ""), (.description // ""), ((.scopes // [])|join(" ")), ((.permissions // [])|join(" "))]
    | join(" ")' | tr "[:upper:]" "[:lower:]")

  cred=1; inj=1; reach=1; reach_exec=1
  printf '%s\n' "$caps" | while IFS= read -r line; do :; done
  # axis presence
  if printf '%s' "$caps" | grep -qiE "$(printf '%s' "$CRED_SIG" | tr ' ' '|')"; then cred=0; fi
  if printf '%s' "$caps" | grep -qiE "$(printf '%s' "$INJ_SIG" | tr ' ' '|')"; then inj=0; fi
  if printf '%s' "$caps" | grep -qiE "$(printf '%s' "$REACH_SIG" | tr ' ' '|')"; then reach=0; fi
  if printf '%s' "$caps" | grep -qiE "$(printf '%s' "$EXEC_TOK" | tr ' ' '|')"; then reach_exec=0; fi

  present=0
  [ "$cred" -eq 0 ] && present=$((present + 1))
  [ "$inj" -eq 0 ] && present=$((present + 1))
  [ "$reach" -eq 0 ] && present=$((present + 1))

  if [ "$present" -eq 3 ]; then
    note "critical" "$name" "Lethal trifecta: credentials + injection + reach"
  elif [ "$present" -eq 2 ]; then
    note "high" "$name" "Two of three trifecta axes present"
  fi
  if [ "$inj" -eq 0 ] && [ "$reach_exec" -eq 0 ]; then
    note "critical" "$name" "Untrusted input can reach code execution"
  fi

  i=$((i + 1))
done

if [ "$format" = "json" ]; then
  printf '{\n  "agents_scanned": %s,\n  "finding_count": %s,\n  "worst_severity": "%s",\n  "findings": [\n' \
    "$agent_count" "$finding_count" "${worst:-none}"
  n=0
  printf '%b' "$findings_out" | while IFS="$(printf '\t')" read -r sev agent title; do
    [ -z "$sev" ] && continue
    n=$((n + 1))
    sep=","
    [ "$n" -eq "$finding_count" ] && sep=""
    printf '    {"agent": "%s", "severity": "%s", "title": "%s"}%s\n' "$agent" "$sev" "$title" "$sep"
  done
  printf '  ]\n}\n'
else
  printf 'AEGIS audit | agents: %s | findings: %s | worst: %s\n' \
    "$agent_count" "$finding_count" "${worst:-none}"
  printf '%b' "$findings_out" | while IFS="$(printf '\t')" read -r sev agent title; do
    [ -z "$sev" ] && continue
    up=$(printf '%s' "$sev" | tr "[:lower:]" "[:upper:]")
    printf '[%-8s] %s: %s\n' "$up" "$agent" "$title"
  done
fi

case "${worst:-none}" in critical|high) exit 1 ;; esac
exit 0

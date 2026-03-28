#!/bin/bash
#/usr/local/bin/ntfy-alert.sh
# Central notification dispatcher
# CHANGE THESE TWO VALUES — this is the only place to update them
NTFY_URL="https://ntfy.lrk.cx"
NTFY_TOPIC="CHANGEME_server_alerts"
NTFY_TOKEN="tk_CHANGEME"

TITLE="${1:-Alert}"
MESSAGE="${2:-No message provided}"
PRIORITY="${3:-default}"
HOSTNAME="$(hostname -s)"

curl -sf \
  -H "Authorization: Bearer ${NTFY_TOKEN}" \
  -H "Title: [${HOSTNAME}] ${TITLE}" \
  -H "Priority: ${PRIORITY}" \
  -H "Tags: warning" \
  -d "${MESSAGE}" \
  "${NTFY_URL}/${NTFY_TOPIC}" \
  > /dev/null 2>&1

# Exit silently — a failed notification must never break the calling process
exit 0

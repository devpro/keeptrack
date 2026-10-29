#!/usr/bin/env bash
# Puts the reference data provider keys of Local.runsettings on a sidelab launcher, as secrets of the signed-in account,
# under the names lab.yaml declares, so a lab session receives them without any value being typed, printed or written to a file.
#
# Usage: LAUNCHER_URL=http://localhost:<port> [ADMIN_USERNAME=admin] [ADMIN_PASSWORD=<password>] labs/set_sidelab_secrets.sh
set -euo pipefail

: "${LAUNCHER_URL:?LAUNCHER_URL is the launcher, for example http://localhost:44825}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-verify-course-local-pass}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The runsettings values are loaded with the script, since sourcing them as NAME=value lines silently drops a `$` (see CONTRIBUTING.md#tests).
eval "$(node "${REPO_DIR}/scripts/load-runsettings.js" 2>/dev/null)"

jwt=$(curl -sf -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$ADMIN_USERNAME" --arg p "$ADMIN_PASSWORD" '{username: $u, password: $p}')" \
  "${LAUNCHER_URL}/api/auth/login" | jq -r .token)

# Lab secret name, then the runsettings variable holding its value.
pairs=(
  TMDB_APIKEY Tmdb__ApiKey
  OMDB_APIKEY Omdb__ApiKey
  IGDB_CLIENTID Igdb__ClientId
  IGDB_CLIENTSECRET Igdb__ClientSecret
  RAWG_APIKEY Rawg__ApiKey
  DISCOGS_TOKEN Discogs__Token
  GOOGLEBOOKS_APIKEY GoogleBooks__ApiKey
)

for ((i = 0; i < ${#pairs[@]}; i += 2)); do
  name=${pairs[i]}
  value=${!pairs[i + 1]:-}
  if [ -z "$value" ]; then
    echo "${name}: no ${pairs[i + 1]} in Local.runsettings, left unset"
    continue
  fi
  status=$(jq -n --arg v "$value" '{value: $v, secret: true}' |
    curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer ${jwt}" -H 'Content-Type: application/json' \
      --data @- "${LAUNCHER_URL}/api/profile/secrets/${name}")
  echo "${name}: ${status}"
done

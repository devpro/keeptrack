#!/usr/bin/env bash
# Prepares a fresh machine for every test suite: the indexes of both test databases, and the browser of the end-to-end tests.
# The browser is installed by the restored package rather than by the playwright.ps1 of a build,
# since code built before the Sonar scanner starts is not analyzed.
set -euo pipefail

cd "$(dirname "$0")/.."

mongodb="${Infrastructure__MongoDB__ConnectionString:-mongodb://localhost:27017}"
for database in "${Infrastructure__MongoDB__DatabaseName:-keeptrack_integrationtests}" "${E2E_MONGODB_DATABASE:-keeptrack_e2e}"; do
  mongosh --quiet "${mongodb%/}/${database}" scripts/mongodb-create-index.js
done

version="$(sed -nE 's/.*Include="Microsoft\.Playwright[^"]*" Version="([^"]+)".*/\1/p' Directory.Packages.props | head -1)"
playwright="${NUGET_PACKAGES:-$HOME/.nuget/packages}/microsoft.playwright/${version}/.playwright"
"${playwright}/node/linux-x64/node" "${playwright}/package/cli.js" install --only-shell chromium

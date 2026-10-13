#!/usr/bin/env bash
set -euo pipefail

# The runner image has no sudo, so MongoDB comes from its tarball into the temporary directory instead of the apt package.
echo "Install and start MongoDB 8.2"
MONGODB_HOME="${RUNNER_TEMP:-$(mktemp -d)}/mongodb"
mkdir -p "${MONGODB_HOME}/bin" "${MONGODB_HOME}/data"
curl --proto "=https" --tlsv1.2 -fsSL https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2404-8.2.1.tgz |
  tar xz --strip-components=2 -C "${MONGODB_HOME}/bin" --wildcards "*/bin/mongod"
"${MONGODB_HOME}/bin/mongod" --dbpath "${MONGODB_HOME}/data" --bind_ip 127.0.0.1 \
  --fork --logpath "${MONGODB_HOME}/mongod.log"
timeout 30 bash -c "
  until (echo > /dev/tcp/127.0.0.1/27017) 2>/dev/null; do
    echo 'MongoDB not ready yet, retrying in 1 second...'
    sleep 1
  done
"

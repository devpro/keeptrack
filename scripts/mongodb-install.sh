#!/usr/bin/env bash
set -euo pipefail

echo "Install and start MongoDB 8.2"
curl --tlsv1.2 -sSf -L https://www.mongodb.org/static/pgp/server-8.0.asc | \
  sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg \
  --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.2 multiverse" |
  sudo tee /etc/apt/sources.list.d/mongodb-org-8.2.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo systemctl start mongod
timeout 30 bash -c "
  until mongosh --host localhost:27017 --eval 'db.runCommand({ ping: 1 })' >/dev/null 2>&1; do
    echo 'MongoDB not ready yet, retrying in 1 second...'
    sleep 1
  done
"

#!/bin/sh
# Safe update: keeps every account, project and database (they live in /srv/hosting, outside the container).
set -e
cd "$(dirname "$0")"
mkdir -p /srv/hosting/backups
[ -f /srv/hosting/state.json ] && cp /srv/hosting/state.json "/srv/hosting/backups/state-$(date +%Y%m%d-%H%M%S).json"
docker compose up -d --build
echo "Updated. Accounts are kept (MongoDB if MONGO_URI / ADMIN_DB_MONGO is set, plus /srv/hosting)."

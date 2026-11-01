#!/bin/sh
# Start the built-in databases without docker compose: sh start-dbs.sh
# (PostgreSQL + MongoDB + MySQL). Safe to run again: existing containers are just started.
set -e
cd "$(dirname "$0")"
set -a
[ -f .env ] && . ./.env
set +a

: "${MONGO_ROOT_PASSWORD:=change-me}"
: "${POSTGRES_PASSWORD:=change-me}"
: "${MYSQL_ROOT_PASSWORD:=change-me}"

mkdir -p /srv/hosting/db/mongo /srv/hosting/db/postgres /srv/hosting/db/mysql
docker network create stark_net >/dev/null 2>&1 || true

run() {
	name="$1"; shift
	if docker inspect "$name" >/dev/null 2>&1; then
		docker start "$name" >/dev/null 2>&1 || true
	else
		docker run -d --name "$name" --restart unless-stopped --network stark_net "$@" >/dev/null
	fi
}

run stark_postgres -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
	-v /srv/hosting/db/postgres:/var/lib/postgresql/data postgres:16-alpine
run stark_mongo -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD="$MONGO_ROOT_PASSWORD" \
	-v /srv/hosting/db/mongo:/data/db mongo:7 --wiredTigerCacheSizeGB 0.5
run stark_mysql -e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASSWORD" \
	-v /srv/hosting/db/mysql:/var/lib/mysql mysql:8

echo "Built-in databases:"
docker ps --format '  {{.Names}}  {{.Status}}' | grep stark_ || true

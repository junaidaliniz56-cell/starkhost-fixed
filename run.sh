#!/bin/sh
# Start command for hosts without docker compose:  sh run.sh
cd "$(dirname "$0")"
go mod tidy && go build -o nova . && exec ./nova

#!/bin/bash
# Build + start the Authentic2 container for the SAML DoS study.
#   ./run.sh            interactive: follow the log (Ctrl-C stops the container)
#   DETACH=1 ./run.sh   start and return (used by harness/spinup.sh)
# Knobs: WORKERS (gunicorn pool, default 16), PORT (default 8092).
set -eu
cd "$(dirname "$0")/../.."          # repo root: the build context
WORKERS="${WORKERS:-16}"
PORT="${PORT:-8092}"
DETACH="${DETACH:-0}"

echo "[*] building authentic2-poc (first build pulls Django + python-ldap, several minutes)"
docker build -f poc/docker/Dockerfile -t authentic2-poc .   # not -q: a silent build failure looks like 'nothing happened'

# PostgreSQL is REQUIRED: authentic2 migrations use PG-only index operator classes
# (custom_user.0022_index_email -> text_pattern_ops), which SQLite cannot apply.
docker network create authentic2-net >/dev/null 2>&1 || true
docker rm -f authentic2-poc authentic2-db >/dev/null 2>&1 || true
docker run -d --name authentic2-db --network authentic2-net \
  -e POSTGRES_USER=authentic2 -e POSTGRES_PASSWORD=authentic2 -e POSTGRES_DB=authentic2 \
  postgres:15 >/dev/null
echo "[*] waiting for postgres"
for _ in $(seq 1 60); do
  docker exec authentic2-db pg_isready -U authentic2 >/dev/null 2>&1 && break; sleep 2
done
docker run -d --name authentic2-poc --network authentic2-net -e WORKERS="$WORKERS" \
  -p 127.0.0.1:${PORT}:80 authentic2-poc >/dev/null
echo "[*] authentic2-poc up on http://localhost:${PORT}  (gunicorn workers=${WORKERS})"
echo "    SAML IdP SSO: /idp/saml2/sso     SP ACS (mellon): /accounts/saml/login/"

if [ "$DETACH" = 1 ]; then
  echo "    watch: docker logs -f authentic2-poc"
else
  docker logs -f authentic2-poc
fi

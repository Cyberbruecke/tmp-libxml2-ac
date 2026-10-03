#!/usr/bin/env bash
# Bring up a self-contained SimpleSAMLphp SP (latest release) on the production-common
# web tier -- Apache with mpm_prefork + mod_php -- at http://localhost:8090, then
# reproduce the pre-auth attribute-flood CPU-DoS.
#
#   ./run.sh
#   python3 saml_acs_poc.py 48000                 # one ~0.5 MB request -> ~11 s pre-auth CPU
#   python3 worker_exhaustion_demo.py 8 32000        # concurrent floods -> pool exhaustion

set -euo pipefail
cd "$(dirname "$0")"

docker rm -f ssp-sp
echo "[*] building the SimpleSAMLphp SP image (composer install ~3-5 min first time)"
docker build -t ssp-sp .

echo "[*] (re)starting the container on 127.0.0.1:8090"
docker rm -f ssp-sp >/dev/null 2>&1 || true
docker run -d --name ssp-sp -p 127.0.0.1:8090:80 ssp-sp >/dev/null

echo "[*] waiting for Apache..."
for _ in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:8090/ 2>/dev/null && break; sleep 2
done

if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/ | grep -qE '30[0-9]|200'; then
  cat <<'EOF'

[[ok]] SimpleSAMLphp SP up at http://localhost:8090  (Apache mpm_prefork + mod_php)
    ACS: http://localhost:8090/module.php/saml/sp/saml2-acs.php/default-sp
    Reproduce the pre-auth attribute-flood DoS:
      python3 saml_acs_poc.py 48000            # ~0.5 MB -> ~11 s on one worker
      python3 worker_exhaustion_demo.py 8 32000   # concurrent floods + a legit probe
    Wipe: docker rm -f ssp-sp
EOF
else
  echo "[!] SP did not come up; check: docker logs ssp-sp"; exit 1
fi

# DETACH=1 -> start and return (scripted use via harness/spinup.sh);
# default stays interactive and follows the log.
if [ "${DETACH:-0}" = 1 ]; then
  echo "ssp-sp started in the background.  watch: docker logs -f ssp-sp"
else
  docker logs -f ssp-sp
fi
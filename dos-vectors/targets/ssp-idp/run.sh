#!/usr/bin/env bash
# Bring up a self-contained SimpleSAMLphp IdP (latest release) on the production-common
# web tier -- Apache with mpm_prefork + mod_php -- at http://localhost:8091, then
# reproduce the pre-auth xmlReconciliateNs CPU-DoS on its SSO endpoint.
#
#   ./run.sh
#   python3 saml_sso_poc.py 48                        # one ~0.3 MB AuthnRequest -> ~12 s pre-auth CPU
#   python3 worker_exhaustion_demo.py 8 32            # concurrent floods -> pool exhaustion
#
# Wipe: docker rm -f ssp-idp
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] building the SimpleSAMLphp IdP image (composer install ~3-5 min first time)"
docker build -t ssp-idp .

echo "[*] (re)starting the container on 127.0.0.1:8091"
docker rm -f ssp-idp >/dev/null 2>&1 || true
docker run -d --name ssp-idp -p 127.0.0.1:8091:80 ssp-idp >/dev/null

echo "[*] waiting for Apache..."
for _ in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:8091/ 2>/dev/null && break; sleep 2
done

if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8091/ | grep -qE '30[0-9]|200'; then
  cat <<'EOF'

[[ok]] SimpleSAMLphp IdP up at http://localhost:8091  (Apache mpm_prefork + mod_php)
    SSO: http://localhost:8091/module.php/saml/idp/singleSignOnService
    Reproduce the pre-auth xmlReconciliateNs DoS:
      python3 saml_sso_poc.py 48                 # ~0.3 MB AuthnRequest -> ~12 s on one worker
      python3 worker_exhaustion_demo.py 8 32     # concurrent floods + a legit probe
    Wipe: docker rm -f ssp-idp
EOF
else
  echo "[!] IdP did not come up; check: docker logs ssp-idp"; exit 1
fi

# DETACH=1 -> start and return (scripted use via harness/spinup.sh);
# default stays interactive and follows the log.
if [ "${DETACH:-0}" = 1 ]; then
  echo "ssp-idp started in the background.  watch: docker logs -f ssp-idp"
else
  docker logs -f ssp-idp
fi
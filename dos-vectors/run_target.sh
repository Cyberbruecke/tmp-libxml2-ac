#!/usr/bin/env bash
# run_target.sh -- self-contained spinup for the SAML targets (rework/ canonical).
# No dependency on the colleague's spinup.sh / targets/*; the only build assets live under
# rework/targets/{ssp-idp,ssp-sp,authentic2}. Host needs: docker (+ curl, openssl). Builds run
# in containers, so no host git/php/composer/ddev/npm.  LOCAL testing only.
#
#   ./run_target.sh list
#   ./run_target.sh up   <target> [--keep]   # --keep = don't stop the other targets first
#   SIZE=small|medium ./run_target.sh up gitlab|nextcloud   # constrain to a balanced reference box
#                                                 # (4vCPU/8GB | 8vCPU/16GB); default = unconstrained
#   ./run_target.sh down <target|all>
#   ./run_target.sh probe <target>           # liveness of the cheap dynamic endpoint
# then:  python3 fire.py --target <target> --vector <FlAttr|C14N1D3|XPlode|Wreckoncile> --size <n>
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# target -> "container | port | probe-path"  (probe = a cheap worker-served dynamic page)
# NB: `authentik` is a single stack that serves BOTH SAML roles; fire.py splits it into two
# logical targets (authentik-sp = SAML Source ACS, authentik-idp = SAML Provider SSO).
declare -A PORT=( [nextcloud]=8080 [gitlab]=80 [synapse]=8008 [ssp-sp]=8090 [ssp-idp]=8091
                  [authentic2]=8092 [drupal]=8083 [wordpress]=8889
                  [moodle]=8082 [authentik]=9000 )
declare -A PROBE=( [nextcloud]=/status.php [gitlab]=/users/sign_in
                   [synapse]=/_matrix/client/versions [ssp-sp]=/ [ssp-idp]=/
                   [authentic2]=/ [drupal]=/user/login [wordpress]=/
                   [moodle]=/login/index.php [authentik]=/-/health/live/ )
declare -A CNAME=( [nextcloud]=nextcloud-poc [gitlab]=gitlab [synapse]=synapse-poc
                   [ssp-sp]=ssp-sp [ssp-idp]=ssp-idp [authentic2]=authentic2-poc
                   [drupal]=drupal-poc [wordpress]=wordpress-poc
                   [moodle]=moodle-poc [authentik]=authentik-server )
ALL="nextcloud gitlab synapse ssp-sp ssp-idp authentic2 drupal wordpress moodle authentik"

# ===== pinned image versions ===============================================
# Reproducibility: these are the exact images the measurements run against.
# Verified present on Docker Hub / ghcr.io on 2026-10-01. Bump deliberately.
# (ssp-sp/ssp-idp use php:8.5.11-apache and authentic2 uses ubuntu:noble-20260911,
#  pinned directly in rework/targets/*/Dockerfile.)
IMG_NEXTCLOUD=nextcloud:35.0.1-apache
IMG_MARIADB=mariadb:11.8.9                     # nc-db, drupal-db, wp-db
IMG_COMPOSER=composer:2.10.3
IMG_ALPINE=alpine:3.24.2                        # chown helper containers
IMG_ALPINEGIT=alpine/git:2.54.0
IMG_GITLAB=gitlab/gitlab-ee:19.4.1-ee.0
IMG_SYNAPSE=matrixdotorg/synapse:v1.162.0
IMG_POSTGRES15=postgres:15.19                   # authentic2-db
IMG_POSTGRES16=postgres:16.15-alpine            # authentik-db
IMG_REDIS=redis:7.4-alpine
IMG_DRUPAL=drupal:11.4.8-apache
IMG_WORDPRESS=wordpress:7.1.2-apache
IMG_WPCLI=wordpress:cli-2.12.0
IMG_MOODLE=bitnamilegacy/moodle:5.0.2           # bitnami wiped the public namespace (Aug 2025)
IMG_MOODLE_DB=bitnamilegacy/mariadb:11.8.3      # bitnami-flavoured mariadb for the moodle stack
IMG_AUTHENTIK=ghcr.io/goauthentik/server:2026.8.3
# ===========================================================================

log(){ printf '[*] %s\n' "$*"; }
die(){ printf '[!] %s\n' "$*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

# SIZE=small|medium models a realistically-provisioned box (balanced cores:RAM). Sets the global
# LIMITS to docker cpu/mem flags; --memory-swap==--memory disables swap so an over-budget wave
# actually OOM-kills instead of silently swapping. Default (unset) = unconstrained (whole host).
set_size_limits(){
  case "${SIZE:-}" in
    small)  LIMITS="--cpus=4 --memory=8g --memory-swap=8g";   log "SIZE=small: 4 vCPU / 8 GB";;
    medium) LIMITS="--cpus=8 --memory=16g --memory-swap=16g"; log "SIZE=medium: 8 vCPU / 16 GB";;
    ""|unconstrained|full) LIMITS="";;
    *) die "unknown SIZE '$SIZE' (use: small | medium | unconstrained)";;
  esac
}

wait_http(){ # $1=url  -- accept 2xx/3xx, up to ~12 min (GitLab boots slowly)
  local url="$1" i code
  printf '    waiting for %s (2xx/3xx) ' "$url"
  for i in $(seq 1 150); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null)
    case "$code" in 2??|3??) echo " up ($code)"; return 0 ;; esac
    printf '.'; sleep 5
  done
  echo; return 1
}

stop_others(){ local keep="$1" o; [ "$keep" = "--keep" ] && { log "--keep: leaving others running"; return; }
  log "stopping other targets (one target at a time for clean measurement)"
  for o in $ALL; do [ "$o" = "$TARGET" ] || cmd_down "$o" >/dev/null 2>&1; done; }

idp_cert(){ # writes /tmp/rt_idp.{key,crt}; echoes the base64 body (no PEM header)
  [ -f /tmp/rt_idp.crt ] || openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /tmp/rt_idp.key -out /tmp/rt_idp.crt -days 365 -subj "/CN=evil-idp.test" 2>/dev/null
  grep -v CERTIFICATE /tmp/rt_idp.crt | tr -d '\n'; }

# ---------------------------------------------------------------------------- SSP (build+run)
up_ssp(){ local t="$1"                 # config is baked into the image (see targets/$t/Dockerfile)
  [ -d "$HERE/targets/$t" ] || die "missing $HERE/targets/$t"
  log "building $t image (composer create-project ~3-5 min first time)"
  docker build -t "$t" "$HERE/targets/$t" || die "$t build failed"
  docker rm -f "$t" >/dev/null 2>&1 || true
  local LIMITS; set_size_limits   # SIZE caps the mpm_prefork app container (fixed reference box)
  docker run -d --name "$t" -p "127.0.0.1:${PORT[$t]}:80" $LIMITS "$t" >/dev/null || die "$t run failed"
  wait_http "http://127.0.0.1:${PORT[$t]}/" || die "$t never answered"; }

# ---------------------------------------------------------------------------- Nextcloud
up_nextcloud(){
  local C=${CNAME[nextcloud]} P=${PORT[nextcloud]}
  docker rm -f "$C" nc-db >/dev/null 2>&1 || true; docker volume rm nc-poc-data >/dev/null 2>&1 || true
  docker network create nc-net >/dev/null 2>&1 || true
  # Production-realistic DB: SQLite serializes every request on one global write lock (single-writer),
  # which throttles concurrency and masks the real worker-pin. Nextcloud production uses MySQL/PostgreSQL.
  log "starting mariadb + official $IMG_NEXTCLOUD on :$P"
  docker run -d --name nc-db --network nc-net \
    -e MARIADB_DATABASE=nextcloud -e MARIADB_USER=nextcloud -e MARIADB_PASSWORD=nextcloud \
    -e MARIADB_ROOT_PASSWORD=root $IMG_MARIADB >/dev/null
  local i; for i in $(seq 1 60); do docker exec nc-db mariadb -unextcloud -pnextcloud \
    -e 'select 1' nextcloud >/dev/null 2>&1 && break; sleep 2; done
  # SIZE limit applies to the app container (where the mod_php workers + C14N burn live); the DB runs
  # unconstrained. MaxRequestWorkers stays 150 regardless of RAM (prefork isn't memory-aware like Puma),
  # so a small cap + concurrent large canonical buffers is what would OOM a realistic box.
  local LIMITS; set_size_limits
  docker run -d --name "$C" --network nc-net -p "127.0.0.1:$P:80" -v nc-poc-data:/var/www/html $LIMITS \
    -e MYSQL_HOST=nc-db -e MYSQL_DATABASE=nextcloud -e MYSQL_USER=nextcloud -e MYSQL_PASSWORD=nextcloud \
    -e NEXTCLOUD_ADMIN_USER=admin -e NEXTCLOUD_ADMIN_PASSWORD=test1234 \
    -e NEXTCLOUD_TRUSTED_DOMAINS="127.0.0.1 127.0.0.1:$P localhost" $IMG_NEXTCLOUD >/dev/null
  local i; for i in $(seq 1 60); do curl -s "http://127.0.0.1:$P/status.php" | grep -q '"installed":true' && break; sleep 3; done
  log "building user_saml in a composer container (no host php/composer needed)"
  local B; B=$(mktemp -d)
  docker run --rm -v "$B:/out" $IMG_COMPOSER sh -c \
    'git clone --depth 1 https://github.com/nextcloud/user_saml /out/user_saml >/dev/null 2>&1 &&
     cd /out/user_saml && composer install --no-dev --no-interaction --quiet' || die "user_saml build failed"
  # composer ran as root, so $B is root-owned; reclaim it so the `rm -rf "$B"` below can clean up
  # (the app is copied in via `docker cp`, so this is cleanup-hygiene, not a functional fix).
  docker run --rm -v "$B:/out" $IMG_ALPINE chown -R "$(id -u):$(id -g)" /out >/dev/null 2>&1 || true
  docker exec "$C" rm -rf /var/www/html/apps/user_saml
  docker cp "$B/user_saml" "$C:/var/www/html/apps/user_saml"
  docker exec "$C" chown -R www-data:www-data /var/www/html/apps/user_saml; rm -rf "$B"
  local occ="docker exec --user www-data $C php occ"
  $occ app:enable user_saml
  local CERT; CERT=$(idp_cert)
  echo "$(docker exec --user www-data $C php occ saml:config:get --output=json 2>/dev/null)" | grep -q '"1":' \
    || $occ saml:config:create >/dev/null
  $occ saml:config:set 1 --general-uid_mapping=uid \
    --idp-entityId="https://evil-idp.test/metadata" \
    --idp-singleSignOnService.url="https://evil-idp.test/sso" --idp-x509cert="$CERT" >/dev/null
  $occ config:app:set user_saml type --value=saml >/dev/null
  $occ config:app:set user_saml general-allow_multiple_user_back_ends --value=1 >/dev/null
  $occ saml:config:set 1 --security-wantAssertionsSigned=1 >/dev/null   # hardened; sink still fires
  wait_http "http://127.0.0.1:$P/apps/user_saml/saml/login?idp=1" || die "/saml/login not 303"; }

# ---------------------------------------------------------------------------- GitLab
up_gitlab(){
  local C=${CNAME[gitlab]} P=${PORT[gitlab]}
  openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/rt_gl.key -out /tmp/rt_gl.crt \
    -days 365 -subj "/CN=idp.example.test" 2>/dev/null
  local FP; FP=$(openssl x509 -in /tmp/rt_gl.crt -noout -fingerprint -sha1 | sed 's/.*=//')
  docker rm -f "$C" >/dev/null 2>&1 || true
  local LIMITS; set_size_limits   # SIZE=small|medium -> --cpus/--memory (Puma auto-sizes to the grant)
  log "starting $IMG_GITLAB on :$P (SAML baked via GITLAB_OMNIBUS_CONFIG; boots slowly)"
  # --shm-size: Docker defaults /dev/shm to 64MB; GitLab's prometheus-client-mmap writes a metric
  #   file per Puma worker there, and a many-core host spawns enough workers to overflow 64MB ->
  #   ENOSPC in the worker-start hook -> workers crash-loop -> 500s + gigabytes of error logs.
  # prometheus_metrics_enabled=false + prometheus_monitoring['enable']=false: this is a DoS test
  #   box, not a monitored deployment -- turning GitLab's own metrics off removes the /dev/shm
  #   pressure and the log spam entirely (does not affect the SAML path under test).
  # --log-opt caps Docker's captured json log so `docker logs` can't grow without bound.
  docker run -d --name "$C" --hostname gitlab.example.com -p "127.0.0.1:$P:80" \
    --shm-size=512m --log-opt max-size=50m --log-opt max-file=3 $LIMITS \
    -e GITLAB_OMNIBUS_CONFIG="external_url 'http://gitlab.example.com'; \
      prometheus_monitoring['enable']=false; gitlab_rails['prometheus_metrics_enabled']=false; \
      gitlab_rails['omniauth_enabled']=true; gitlab_rails['omniauth_allow_single_sign_on']=['saml']; \
      gitlab_rails['omniauth_block_auto_created_users']=false; gitlab_rails['omniauth_auto_link_saml_user']=true; \
      gitlab_rails['omniauth_providers']=[{name:'saml',label:'SAML',args:{ \
        assertion_consumer_service_url:'http://gitlab.example.com/users/auth/saml/callback', \
        idp_cert_fingerprint:'$FP', idp_sso_target_url:'http://idp.example.test/sso', \
        issuer:'http://gitlab.example.com', \
        name_identifier_format:'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'}}]" \
    $IMG_GITLAB >/dev/null
  wait_http "http://127.0.0.1:$P/users/sign_in" || die "gitlab never answered (docker logs $C)"; }

# ---------------------------------------------------------------------------- Synapse
up_synapse(){
  local C=${CNAME[synapse]} P=${PORT[synapse]} D; D=$(mktemp -d)
  log "generating synapse config (official image includes pysaml2/xmlsec1)"
  docker run --rm -v "$D:/data" -e SYNAPSE_SERVER_NAME=localhost -e SYNAPSE_REPORT_STATS=no \
    $IMG_SYNAPSE generate >/dev/null 2>&1 || true
  # `generate` runs as root and chowns /data to the synapse user, leaving $D unwritable by us;
  # reclaim it so the host-side openssl/cert/metadata/homeserver.yaml writes below don't fail
  # (silent failure here = Synapse boots with NO saml2_config -> SP metadata 404, unusable).
  docker run --rm -v "$D:/data" $IMG_ALPINE chown -R "$(id -u):$(id -g)" /data \
    || die "could not reclaim ownership of synapse config dir"
  local B64; openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/idp.key" -out "$D/idp.crt" \
    -days 365 -subj "/CN=idp.example.test" 2>/dev/null; B64=$(openssl x509 -in "$D/idp.crt" -outform DER | base64 -w0)
  cat > "$D/idp_metadata.xml" <<XML
<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://idp.example.test/metadata">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing">
<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>$B64</X509Certificate></X509Data></KeyInfo>
</KeyDescriptor><NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://idp.example.test/sso"/>
</IDPSSODescriptor></EntityDescriptor>
XML
  grep -q SAML-DOS "$D/homeserver.yaml" 2>/dev/null || cat >> "$D/homeserver.yaml" <<YAML

# --- SAML-DOS (realistic SP config; validation NOT weakened, allow_unsolicited=default False) ---
public_baseurl: "http://localhost:$P/"
saml2_config:
  sp_config:
    metadata: { local: ["/data/idp_metadata.xml"] }
    allow_unknown_attributes: true
  user_mapping_provider:
    config: { mxid_source_attribute: uid, mxid_mapping: dotreplace }
YAML
  docker rm -f "$C" >/dev/null 2>&1 || true
  # --user: the image runs as its built-in uid 991, which can't read our host-owned (mode-700)
  # /data; run synapse as the host user that owns the config dir so it can read/write it. Synapse
  # needs no root, and its start.py skips the root-only chown/gosu path when not uid 0.
  local LIMITS; set_size_limits   # SIZE caps the single-reactor app (fixed reference box)
  docker run -d --name "$C" --user "$(id -u):$(id -g)" $LIMITS \
    -p "127.0.0.1:$P:8008" -v "$D:/data" $IMG_SYNAPSE >/dev/null
  wait_http "http://127.0.0.1:$P/_matrix/client/versions" || die "synapse never answered"
  log "SP metadata: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$P/_synapse/client/saml2/metadata.xml) (200=SAML active)"; }

# ---------------------------------------------------------------------------- Authentic2
up_authentic2(){
  local C=${CNAME[authentic2]} P=${PORT[authentic2]} S; S=$(mktemp -d)
  log "cloning authentic2 source + applying rework overlay (Dockerfile/settings/register)"
  docker run --rm -v "$S:/src" $IMG_ALPINEGIT clone --depth 1 \
    https://git.entrouvert.org/authentic.git /src/authentic >/dev/null 2>&1 \
    || die "authentic2 clone failed (check git.entrouvert.org reachability)"
  # the clone ran as root inside alpine/git, so /src/authentic is root-owned; reclaim it so the
  # host-side mkdir/cp of the overlay below don't hit 'Permission denied'.
  docker run --rm -v "$S:/src" $IMG_ALPINE chown -R "$(id -u):$(id -g)" /src/authentic \
    || die "could not reclaim ownership of cloned authentic2 source"
  mkdir -p "$S/authentic/poc/docker"
  cp "$HERE/targets/authentic2/Dockerfile" "$S/authentic/poc/docker/Dockerfile"
  cp "$HERE/targets/authentic2/settings.py" "$S/authentic/poc/docker/settings.py"
  cp "$HERE/targets/authentic2/register_attack_idp.py" "$S/authentic/poc/register_attack_idp.py"
  log "building authentic2-poc (Django + lasso, several minutes)"
  ( cd "$S/authentic" && docker build -f poc/docker/Dockerfile -t authentic2-poc . ) || die "build failed"
  docker network create authentic2-net >/dev/null 2>&1 || true
  docker rm -f "$C" authentic2-db >/dev/null 2>&1 || true
  docker run -d --name authentic2-db --network authentic2-net \
    -e POSTGRES_USER=authentic2 -e POSTGRES_PASSWORD=authentic2 -e POSTGRES_DB=authentic2 $IMG_POSTGRES15 >/dev/null
  local i; for i in $(seq 1 60); do docker exec authentic2-db pg_isready -U authentic2 >/dev/null 2>&1 && break; sleep 2; done
  local LIMITS; set_size_limits   # SIZE caps the gunicorn app container (fixed reference box)
  docker run -d --name "$C" --network authentic2-net -e WORKERS=16 -p "127.0.0.1:$P:80" $LIMITS authentic2-poc >/dev/null
  wait_http "http://127.0.0.1:$P/" || die "authentic2 never answered"; rm -rf "$S"; }

# ---------------------------------------------------------------------------- Drupal (samlauth)
up_drupal(){
  local C=${CNAME[drupal]} P=${PORT[drupal]} base="http://localhost:${PORT[drupal]}" T; T=$(mktemp -d)
  docker rm -f "$C" drupal-db >/dev/null 2>&1 || true; docker network create drupal-net >/dev/null 2>&1 || true
  # Production-realistic DB: SQLite serializes every request on one global write lock (single-writer),
  # masking the real prefork worker-pin. Drupal production uses MySQL/MariaDB or PostgreSQL.
  log "starting mariadb + official $IMG_DRUPAL on :$P (composer require samlauth ~few min)"
  docker run -d --name drupal-db --network drupal-net \
    -e MARIADB_DATABASE=drupal -e MARIADB_USER=drupal -e MARIADB_PASSWORD=drupal \
    -e MARIADB_ROOT_PASSWORD=root $IMG_MARIADB >/dev/null
  local i; for i in $(seq 1 60); do docker exec drupal-db mariadb -udrupal -pdrupal \
    -e 'select 1' drupal >/dev/null 2>&1 && break; sleep 2; done
  local LIMITS; set_size_limits   # SIZE=small|medium constrains the app container (150 prefork workers)
  docker run -d --name "$C" --network drupal-net -p "127.0.0.1:$P:80" $LIMITS $IMG_DRUPAL >/dev/null \
    || die "drupal run failed"
  for i in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 2; done
  docker exec "$C" bash -c 'printf "memory_limit=256M\nmax_execution_time=30\n" >/usr/local/etc/php/conf.d/dos.ini'
  local drush="docker exec -w /opt/drupal $C vendor/bin/drush -y"
  log "composer require drush + samlauth (in-container)"
  docker exec -w /opt/drupal "$C" composer require drush/drush drupal/samlauth --no-interaction -q || die "composer require failed"
  log "drush site:install (mariadb) + enable samlauth"
  $drush site:install standard --db-url="mysql://drupal:drupal@drupal-db/drupal" \
    --account-pass=admin --site-name=DOS >/dev/null 2>&1 || die "drush si failed"
  $drush config:delete samlauth.authentication >/dev/null 2>&1 || true
  $drush en samlauth >/dev/null 2>&1 || die "drush en samlauth failed"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/idp.key" -out "$T/idp.crt" -days 365 -subj "/CN=evil-idp.test" 2>/dev/null
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$T/sp.key"  -out "$T/sp.crt"  -days 365 -subj "/CN=localhost" 2>/dev/null
  local IDP SP SPK; IDP=$(grep -v CERTIFICATE "$T/idp.crt"|tr -d '\n')
  SP=$(grep -v CERTIFICATE "$T/sp.crt"|tr -d '\n'); SPK=$(grep -v 'PRIVATE KEY' "$T/sp.key"|tr -d '\n')
  cat > "$T/conf.php" <<PHP
<?php
\$c=\Drupal::configFactory()->getEditable('samlauth.authentication');
\$c->set('sp_entity_id','$base/saml/metadata')->set('sp_x509_certificate','$SP')->set('sp_private_key','$SPK')
  ->set('idp_entity_id','https://evil-idp.test/metadata')->set('idp_single_sign_on_service','https://evil-idp.test/sso')
  ->set('idp_single_log_out_service','https://evil-idp.test/slo')->set('idp_certs',['$IDP'])
  ->set('security_messages_sign',TRUE)->set('security_assertions_signed',TRUE)->save();
PHP
  docker cp "$T/conf.php" "$C:/tmp/conf.php"
  $drush php:script /tmp/conf.php >/dev/null 2>&1 || die "samlauth config failed"; rm -rf "$T"
  log "GET /saml/acs -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$P/saml/acs) (302/303 = route live)"; }

# ---------------------------------------------------------------------------- WordPress (miniOrange)
up_wordpress(){
  local C=${CNAME[wordpress]} P=${PORT[wordpress]}
  docker rm -f "$C" wp-db >/dev/null 2>&1 || true; docker network create wp-net >/dev/null 2>&1 || true
  log "starting mariadb + official $IMG_WORDPRESS on :$P"
  docker run -d --name wp-db --network wp-net -e MARIADB_DATABASE=wp -e MARIADB_USER=wp \
    -e MARIADB_PASSWORD=wp -e MARIADB_ROOT_PASSWORD=root $IMG_MARIADB >/dev/null
  local i; for i in $(seq 1 60); do docker exec wp-db mariadb -uwp -pwp -e 'select 1' wp >/dev/null 2>&1 && break; sleep 2; done
  local LIMITS; set_size_limits   # SIZE caps the mpm_prefork app container (fixed reference box)
  docker run -d --name "$C" --network wp-net -p "127.0.0.1:$P:80" $LIMITS \
    -e WORDPRESS_DB_HOST=wp-db -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp $IMG_WORDPRESS >/dev/null
  for i in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 2; done
  # the WP entrypoint writes wp-config.php on first boot; wp-cli fails ("please run wp config create")
  # if it runs before that lands, so wait for the file to exist before invoking the CLI.
  for i in $(seq 1 40); do docker exec "$C" test -f /var/www/html/wp-config.php && break; sleep 2; done
  docker exec "$C" bash -c 'printf "memory_limit=256M\nmax_execution_time=30\n" >/usr/local/etc/php/conf.d/dos.ini' 2>/dev/null || true
  # NOTE: trailing `wp` is required -- the $IMG_WPCLI entrypoint only auto-prepends `wp` for
  # args starting with `-`, so a bare `core install` would exec as a command ("core: not found").
  local WP="docker run --rm --network wp-net --volumes-from $C -u 33 \
    -e WORDPRESS_DB_HOST=wp-db -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp $IMG_WPCLI wp"
  log "wp core install + miniOrange SP plugin (install & activate)"
  local out
  out=$($WP core install --url="http://localhost:$P" --title=DOS --admin_user=admin \
    --admin_password=admin --admin_email=admin@example.com --skip-email 2>&1) \
    || { printf '    wp-cli: %s\n' "$out" >&2; die "wp core install failed (error above)"; }
  $WP plugin install miniorange-saml-20-single-sign-on --activate >/dev/null 2>&1 \
    || die "miniOrange plugin install failed"
  $WP config set WP_DEBUG false --raw --type=constant >/dev/null 2>&1 || true
  log "miniOrange SP active; the sink fires on ANY POST SAMLResponse (fire.py sends RelayState=/). \
No IdP config needed (plugin hooks init before the config checks)."; }

# ---------------------------------------------------------------------------- Moodle (auth_saml2)
# Moodle's auth_saml2 plugin EMBEDS SimpleSAMLphp (vendor/simplesamlphp), so the sink surface is
# identical to ssp-sp -- C5/attr on SubjectConfirmationData + C14N on the signature. Built to CONFIRM
# the embedding doesn't change that. Apache mpm_prefork behind, so the same worker-pin denial model.
# ACS = /auth/saml2/sp/saml2-acs.php/<spname>, where spname = the wwwroot HOSTNAME (-> "localhost").
up_moodle(){
  local C=${CNAME[moodle]} P=${PORT[moodle]}
  docker rm -f "$C" moodle-db >/dev/null 2>&1 || true
  docker volume rm moodle-data moodle-db-data >/dev/null 2>&1 || true
  docker network create moodle-net >/dev/null 2>&1 || true
  log "starting $IMG_MOODLE_DB + $IMG_MOODLE on :$P (first install ~3-5 min)"
  docker run -d --name moodle-db --network moodle-net \
    -e MARIADB_DATABASE=bitnami_moodle -e MARIADB_USER=bn_moodle -e MARIADB_PASSWORD=bitnami \
    -e ALLOW_EMPTY_PASSWORD=yes -e MARIADB_CHARACTER_SET=utf8mb4 -e MARIADB_COLLATE=utf8mb4_unicode_ci \
    -v moodle-db-data:/bitnami/mariadb $IMG_MOODLE_DB >/dev/null
  local i; for i in $(seq 1 60); do docker exec moodle-db mariadb -ubn_moodle -pbitnami \
    -e 'select 1' bitnami_moodle >/dev/null 2>&1 && break; sleep 2; done
  local LIMITS; set_size_limits   # SIZE caps the app container (mpm_prefork workers)
  docker run -d --name "$C" --network moodle-net -p "127.0.0.1:$P:8080" -v moodle-data:/bitnami/moodle $LIMITS \
    -e MOODLE_DATABASE_HOST=moodle-db -e MOODLE_DATABASE_NAME=bitnami_moodle \
    -e MOODLE_DATABASE_USER=bn_moodle -e MOODLE_DATABASE_PASSWORD=bitnami \
    -e MOODLE_USERNAME=admin -e MOODLE_PASSWORD=admin123ABC# -e MOODLE_EMAIL=admin@example.com \
    -e MOODLE_SITE_NAME=DOS -e MOODLE_HOST="localhost:$P" $IMG_MOODLE >/dev/null
  wait_http "http://127.0.0.1:$P/login/index.php" || die "moodle never answered"
  # Bitnami symlinks /opt/bitnami/moodle -> the /bitnami/moodle volume, so clone the plugin straight
  # into the volume (no git needed inside the moodle image), then run the CLI upgrade to install it.
  log "installing auth_saml2 (catalyst) + admin/cli/upgrade"
  docker run --rm -v moodle-data:/m $IMG_ALPINEGIT clone --depth 1 -b MOODLE_500_STABLE \
    https://github.com/catalyst/moodle-auth_saml2 /m/auth/saml2 >/dev/null 2>&1 || die "auth_saml2 clone failed"
  # auth_saml2 EMBEDS SimpleSAMLphp as a composer dependency; a bare git clone has no vendor/, so
  # the plugin 500s (metadata/ACS fail to load) and admin/cli/upgrade.php fails. Pull it with a
  # composer container (same pattern as nextcloud's user_saml build).
  # auth_saml2 applies 6 patches to SimpleSAMLphp via cweagans/composer-patches, which shells out
  # to `patch` -- ensure it's present. Capture output so a failure is visible, not swallowed.
  local cout
  cout=$(docker run --rm -v moodle-data:/m $IMG_COMPOSER sh -c \
    'command -v patch >/dev/null 2>&1 || apk add --no-cache patch >/dev/null 2>&1 || true; \
     cd /m/auth/saml2 && composer install --no-dev --no-interaction' 2>&1) \
    || { printf "%s\n" "$cout" | tail -25 | sed "s/^/    composer: /" >&2; die "auth_saml2 composer install failed (see above)"; }
  docker run --rm -v moodle-data:/m $IMG_ALPINE chown -R 1001:1001 /m/auth/saml2 >/dev/null 2>&1 || true
  docker exec "$C" php /opt/bitnami/moodle/admin/cli/upgrade.php --non-interactive --allow-unstable \
    >/dev/null 2>&1 || die "moodle plugin upgrade failed (docker logs $C)"
  # Configure an OFFLINE IdP (XML blob, no network) and enable the auth method. auth_saml2 auto-mints
  # its own SP cert on first metadata build; validation is NOT weakened (sink fires pre-signature).
  local B64 IDPMETA; B64=$(idp_cert)
  IDPMETA="<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://evil-idp.test/metadata\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>$B64</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://evil-idp.test/sso\"/></md:IDPSSODescriptor></md:EntityDescriptor>"
  docker exec "$C" php /opt/bitnami/moodle/admin/cli/cfg.php --component=auth_saml2 --name=idpmetadata --set="$IDPMETA" >/dev/null 2>&1 || true
  docker exec "$C" php /opt/bitnami/moodle/admin/cli/cfg.php --name=auth --set=saml2 >/dev/null 2>&1 || true
  # The admin/cli/* calls above run as root (docker exec default) and create root-owned dirs under
  # dataroot; the Apache/PHP worker runs as "daemon" (the owner of /bitnami/moodledata) and then
  # can't create the SSP cert/config dir -> "Invalid permissions" 500 on login & metadata. Hand
  # dataroot back to the web uid so the plugin can mint its SP cert on first metadata build.
  docker exec -u root "$C" chown -R daemon:root /bitnami/moodledata >/dev/null 2>&1 || true
  local ACS; ACS=$(curl -s "http://127.0.0.1:$P/auth/saml2/sp/metadata.php" \
    | grep -o 'AssertionConsumerService[^>]*Location="[^"]*"' | grep -o 'https\?://[^"]*' | head -1)
  log "auth_saml2 ACS (discovered from SP metadata) = ${ACS:-<none; fire.py default is .../saml2-acs.php/localhost>}"; }

# ---------------------------------------------------------------------------- authentik (SP)
# GENUINELY DIFFERENT stack: Python/Django + lxml/xmlsec (not libxml2-in-PHP), gunicorn/uvicorn worker
# pool -- NOT assumable from any existing target, hence tested directly. We drive the SP role only:
#   authentik-sp = SAML Source, ACS /source/saml/dos-src/acs/  (parses+verifies an inbound SAMLResponse
#                  PRE-auth -- the Response IS the credential, so it canonicalizes untrusted XML = sink)
# The IdP/Provider role is intentionally NOT built: authentik parks an unauthenticated AuthnRequest in
# the session and only parses it AFTER its own login, so the IdP path is not a pre-auth DoS target.
# Config is bootstrapped by a blueprint YAML mounted at /blueprints (applied by the worker on startup).
up_authentik(){
  local C=${CNAME[authentik]} P=${PORT[authentik]} BP; BP=$(mktemp -d)
  docker rm -f "$C" authentik-worker authentik-db authentik-redis >/dev/null 2>&1 || true
  docker network create authentik-net >/dev/null 2>&1 || true
  local SECRET=devsecretdevsecretdevsecret0123456789
  docker run -d --name authentik-db --network authentik-net \
    -e POSTGRES_USER=authentik -e POSTGRES_PASSWORD=authentik -e POSTGRES_DB=authentik $IMG_POSTGRES16 >/dev/null
  docker run -d --name authentik-redis --network authentik-net $IMG_REDIS >/dev/null
  local i; for i in $(seq 1 60); do docker exec authentik-db pg_isready -U authentik >/dev/null 2>&1 && break; sleep 2; done
  # Blueprint: a SAML Source (authentik as SP) whose verification_kp is our fake IdP's cert. That
  # cert is the switch that puts authentik on the xmlsec VERIFY path: it canonicalizes the incoming
  # Response (the c14n sink) and only THEN fails the signature check on fire.py's placeholder sig.
  # Leave verification_kp unset and authentik skips verification entirely -> no c14n, no sink. (The
  # IdP-provider half is gone: authentik defers AuthnRequest parsing to post-login, so it is not a
  # pre-auth target.) signed_response+signed_assertion: with a verification_kp set, authentik requires
  # at least one; both on => it canonicalizes whichever half carries the flood. allow_idp_initiated:
  # accept our unsolicited Response (no prior authentik-issued AuthnRequest to match InResponseTo).
  idp_cert >/dev/null                                   # ensure /tmp/rt_idp.crt (the fake IdP cert) exists
  local CERT_PEM; CERT_PEM=$(sed 's/^/        /' /tmp/rt_idp.crt)   # indent under 'certificate_data: |'
  cat > "$BP/dos.yaml" <<YAML
version: 1
metadata:
  name: dos-saml
entries:
  - model: authentik_crypto.certificatekeypair
    id: dos-idp-verify
    identifiers: {name: dos-idp-verify}
    attrs:
      name: dos-idp-verify
      certificate_data: |
$CERT_PEM
  - model: authentik_sources_saml.samlsource
    identifiers: {slug: dos-src}
    attrs:
      name: dos-src
      slug: dos-src
      enabled: true
      sso_url: https://evil-idp.test/sso
      issuer: https://evil-idp.test/metadata
      binding_type: POST
      allow_idp_initiated: true
      verification_kp: !KeyOf dos-idp-verify
      signed_response: true
      signed_assertion: true
      pre_authentication_flow: !Find [authentik_flows.flow, [slug, default-source-pre-authentication]]
      authentication_flow: !Find [authentik_flows.flow, [slug, default-source-authentication]]
      enrollment_flow: !Find [authentik_flows.flow, [slug, default-source-enrollment]]
YAML
  local ENVS="-e AUTHENTIK_SECRET_KEY=$SECRET \
    -e AUTHENTIK_POSTGRESQL__HOST=authentik-db -e AUTHENTIK_POSTGRESQL__USER=authentik \
    -e AUTHENTIK_POSTGRESQL__PASSWORD=authentik -e AUTHENTIK_POSTGRESQL__NAME=authentik \
    -e AUTHENTIK_REDIS__HOST=authentik-redis -e AUTHENTIK_BOOTSTRAP_PASSWORD=admin \
    -e AUTHENTIK_BOOTSTRAP_TOKEN=dostoken -e AUTHENTIK_DISABLE_UPDATE_CHECK=true \
    -e AUTHENTIK_WEB__WORKERS=3 -e AUTHENTIK_WEB__THREADS=4"   # pin concurrency (3x4=12) to the 8-vCPU box;
                                                              # else gunicorn auto-sizes workers to HOST cores
  local LIMITS; set_size_limits
  log "starting authentik server + worker ($IMG_AUTHENTIK)"
  docker run -d --name "$C" --network authentik-net -p "127.0.0.1:$P:9000" $LIMITS $ENVS \
    -v "$BP/dos.yaml:/blueprints/dos.yaml:ro" $IMG_AUTHENTIK server >/dev/null
  docker run -d --name authentik-worker --network authentik-net $ENVS \
    -v "$BP/dos.yaml:/blueprints/dos.yaml:ro" $IMG_AUTHENTIK worker >/dev/null
  wait_http "http://127.0.0.1:$P/-/health/live/" || die "authentik never answered"
  # Wait for the PYTHON backend to actually answer the SAML routes -- a 502/503/000 is just the Go
  # proxy replying while gunicorn is still booting (health/live/ goes 200 well before that). Only a
  # non-gateway, non-404 code means the worker has booted AND applied the blueprint (route resolves).
  local i code; for i in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/source/saml/dos-src/acs/")
    case "$code" in 000|404|502|503|504) sleep 3;; *) break;; esac; done
  log "authentik-sp ACS: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$P/source/saml/dos-src/acs/) \
(not 404/502 = source live; it verifies the Response pre-auth against verification_kp -> the c14n sink)"; }

cmd_up(){ TARGET="$1"; local keep="${2:-}"
  [ -n "${PORT[$TARGET]+x}" ] || die "unknown target '$TARGET' (see: $0 list)"
  have docker || die "docker not found"; have curl || die "curl not found"
  stop_others "$keep"
  log "bringing up $TARGET on 127.0.0.1:${PORT[$TARGET]}"
  case "$TARGET" in
    ssp-sp|ssp-idp) up_ssp "$TARGET" ;;
    nextcloud) up_nextcloud ;; gitlab) up_gitlab ;; synapse) up_synapse ;;
    authentic2) up_authentic2 ;; drupal) up_drupal ;; wordpress) up_wordpress ;;
    moodle) up_moodle ;; authentik) up_authentik ;;
  esac
  echo "[[ok]] $TARGET up. Test:  python3 $HERE/fire.py --target $TARGET --vector C14N1D3 --size 1000 --probe"; }

cmd_down(){ local t="$1"; [ "$t" = all ] && { for t in $ALL; do cmd_down "$t"; done; return; }
  docker rm -f "${CNAME[$t]:-$t}" >/dev/null 2>&1 || true
  [ "$t" = authentic2 ] && docker rm -f authentic2-db >/dev/null 2>&1 || true
  [ "$t" = nextcloud ]  && docker rm -f nc-db >/dev/null 2>&1 || true
  [ "$t" = drupal ]     && docker rm -f drupal-db >/dev/null 2>&1 || true
  [ "$t" = moodle ]     && docker rm -f moodle-db >/dev/null 2>&1 || true
  [ "$t" = authentik ]  && docker rm -f authentik-worker authentik-db authentik-redis >/dev/null 2>&1 || true
  echo "[*] $t stopped"; }

cmd_probe(){ local t="$1"
  [ -n "${PORT[$t]+x}" ] || die "unknown target '$t' (see: $0 list)"
  local u="http://127.0.0.1:${PORT[$t]}${PROBE[$t]}" dt
  dt=$(curl -sk -o /dev/null -w '%{time_total} %{http_code}' --max-time 30 "$u" 2>/dev/null)
  echo "probe $t -> $u : ${dt:-timeout}"; }

case "${1:-list}" in
  list) printf "%-14s %-6s %s\n" TARGET PORT PROBE
        for t in $ALL; do printf "%-14s %-6s %s\n" "$t" "${PORT[$t]}" "${PROBE[$t]}"; done
        echo; echo "up <t> | down <t|all> | probe <t> ; then fire.py --target <t> ..." ;;
  up)    [ $# -ge 2 ] || die "usage: $0 up <target> [--keep]"; cmd_up "$2" "${3:-}" ;;
  down)  cmd_down "${2:-all}" ;;
  probe) [ $# -ge 2 ] || die "usage: $0 probe <target>"; cmd_probe "$2" ;;
  *)     die "usage: $0 {list|up <t> [--keep]|down <t|all>|probe <t>}" ;;
esac

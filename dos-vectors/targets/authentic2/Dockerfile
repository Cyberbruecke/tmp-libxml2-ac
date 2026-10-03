# Authentic2 (Django -> Lasso -> xmlsec1 -> libxml2) for the SAML DoS study.
#
# Why a container: the host copy relies on a hand-built lasso in
# /usr/local/lib/python3/dist-packages and a venv, which is not reproducible for
# disclosure. Debian/Ubuntu ship python3-lasso, so the whole stack is one apt line.
#
# Why gunicorn and not `manage.py runserver`: runserver is single-threaded and dev-only.
# Measuring blackout on it would report an artificial pool of 1 (like Synapse) and say
# nothing about a real deployment. Authentic2 in production runs under a WSGI server with
# a worker pool, so that is what we measure. DEBUG is off for the same reason.
# ubuntu:noble-20260911 = 24.04 LTS snapshot, pinned for reproducibility
FROM ubuntu:noble-20260911
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
# gettext/msgfmt is required: publik_django_templatetags compiles .po at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-dev python3-lasso \
      build-essential libldap2-dev libsasl2-dev libssl-dev \
      xmlsec1 libxml2 libxmlsec1-dev git ca-certificates curl \
      gettext openssl \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
# lasso lives in the system dist-packages; keep it importable alongside the pip installs
ENV PYTHONPATH=/usr/lib/python3/dist-packages
# psycopg2 is needed even on sqlite: authentic2 loads django.contrib.postgres,
# whose apps.py imports psycopg2 at module level regardless of the DB backend.
RUN pip3 install --break-system-packages --no-cache-dir gunicorn psycopg2-binary && \
    pip3 install --break-system-packages --no-cache-dir -e . && \
    python3 -c "import lasso; print('lasso OK', lasso.__file__)"
COPY poc/docker/settings.py /app/container_settings.py
ENV AUTHENTIC2_SETTINGS_FILE=/app/container_settings.py
# WORKERS: gunicorn's rule of thumb is 2*cores+1; kept explicit so the measured pool size
# is a recorded parameter rather than an accident of the host's core count.
# Attacker IdP keypair, baked in so the instance comes up measurable. The signature never
# verifies (that is the point: C14N runs before the crypto check) but Lasso must RESOLVE the
# Issuer first -- without a registered provider it returns PROVIDER_NOT_FOUND before touching
# the signature and the sink never fires (see poc/register_attack_idp.py).
RUN openssl req -x509 -newkey rsa:2048 -keyout /app/attack-idp.key -out /app/attack-idp.crt \
      -days 3650 -nodes -subj "/CN=evil-idp.test" >/dev/null 2>&1
ENV ATTACK_IDP_ENTITY=https://evil-idp.test/
ENV WORKERS=16
EXPOSE 80
CMD sh -c "python3 manage.py migrate --noinput && \
    (python3 poc/register_attack_idp.py --cert /app/attack-idp.crt \
        --entity-id \$ATTACK_IDP_ENTITY --slug attack-idp && echo '[*] attack IdP registered') \
      || echo '[!] IdP registration FAILED -- the C14N sink will not be reachable' && \
    exec gunicorn --workers \$WORKERS --bind 0.0.0.0:80 --timeout 300 \
         --access-logfile - authentic2.wsgi:application"

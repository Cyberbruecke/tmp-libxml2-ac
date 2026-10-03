# A self-contained SimpleSAMLphp IdP (latest release) on the production-common web tier:
# Apache with mpm_prefork + mod_php (NOT the php -S dev server). Attacks the IdP: an
# attacker AuthnRequest carrying a namespace-flooded Extensions is saved to state
# (importNode = xmlDocCopyNode + xmlReconciliateNs) O(N^2), before the user ever logs in.
FROM php:8.5.11-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
      git unzip libzip-dev libonig-dev libxml2 \
    && docker-php-ext-install zip mbstring bcmath \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Production-common: Apache prefork + mod_php.
RUN a2dismod mpm_event 2>/dev/null || true; a2enmod mpm_prefork rewrite

# Latest SimpleSAMLphp.
RUN composer create-project --no-dev --no-interaction "simplesamlphp/simplesamlphp:^2" /var/www/ssp

# Serve SSP's public/ dir.
RUN sed -ri 's!/var/www/html!/var/www/ssp/public!g' \
      /etc/apache2/sites-available/000-default.conf /etc/apache2/apache2.conf \
 && printf '<Directory /var/www/ssp/public>\n  AllowOverride All\n  Require all granted\n</Directory>\n' \
      > /etc/apache2/conf-available/ssp.conf && a2enconf ssp

# IdP config: authsource + hosted/remote-SP metadata.
COPY ssp-config/authsources.php /var/www/ssp/config/authsources.php
COPY ssp-config/metadata/saml20-idp-hosted.php /var/www/ssp/metadata/saml20-idp-hosted.php
COPY ssp-config/metadata/saml20-sp-remote.php /var/www/ssp/metadata/saml20-sp-remote.php

# IdP signing cert (cert/ is SSP's default certdir).
RUN mkdir -p /var/www/ssp/cert \
 && openssl req -x509 -newkey rsa:2048 -nodes -keyout /var/www/ssp/cert/server.pem \
      -out /var/www/ssp/cert/server.crt -days 3650 -subj "/CN=idp.test" 2>/dev/null

# Activate config (SSP 2.x ships config.php.dist), enable the IdP role, point at :8091,
# set a real secretsalt, trust localhost.
RUN cd /var/www/ssp \
 && cp config/config.php.dist config/config.php \
 && SALT="$(php -r 'echo bin2hex(random_bytes(16));')" \
 && sed -i "s#'baseurlpath' => '[^']*'#'baseurlpath' => 'http://localhost:8091/'#" config/config.php \
 && sed -i "s#'secretsalt' => '[^']*'#'secretsalt' => '$SALT'#" config/config.php \
 && sed -i "s#'trusted.url.domains' => \[\]#'trusted.url.domains' => ['localhost:8091','localhost']#" config/config.php \
 && sed -i "s#'enable.saml20-idp' => false#'enable.saml20-idp' => true#" config/config.php

# Writable cache/log dirs for the www-data runtime user.
RUN mkdir -p /var/cache/simplesamlphp /var/www/ssp/log \
 && chown -R www-data:www-data /var/cache/simplesamlphp /var/www/ssp/log \
      /var/www/ssp/config /var/www/ssp/metadata /var/www/ssp/cert

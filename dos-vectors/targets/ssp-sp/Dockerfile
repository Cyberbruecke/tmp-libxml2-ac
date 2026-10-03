# A self-contained SimpleSAMLphp SP (latest release) on the production-common web
# tier: Apache with mpm_prefork + mod_php (NOT the php -S dev server). One SP
# ("default-sp") pointing at a forged test IdP is all the attribute flood attack needs: the
# O(N^2) re-serialization of the inbound Response runs before the signature check.
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

# SP + forged IdP config.
COPY ssp-config/authsources.php /var/www/ssp/config/authsources.php
COPY ssp-config/metadata/saml20-idp-remote.php /var/www/ssp/metadata/saml20-idp-remote.php

# Activate config (SSP 2.x ships config.php.dist), point it at http://localhost:8090/,
# set a real secretsalt, and trust localhost. (authsources.php was copied above.)
RUN cd /var/www/ssp \
 && cp config/config.php.dist config/config.php \
 && SALT="$(php -r 'echo bin2hex(random_bytes(16));')" \
 && sed -i "s#'baseurlpath' => '[^']*'#'baseurlpath' => 'http://localhost:8090/'#" config/config.php \
 && sed -i "s#'secretsalt' => '[^']*'#'secretsalt' => '$SALT'#" config/config.php \
 && sed -i "s#'trusted.url.domains' => \[\]#'trusted.url.domains' => ['localhost:8090','localhost']#" config/config.php

# Writable cache/log dirs for the www-data runtime user.
RUN mkdir -p /var/cache/simplesamlphp /var/www/ssp/log \
 && chown -R www-data:www-data /var/cache/simplesamlphp /var/www/ssp/log /var/www/ssp/config /var/www/ssp/metadata

"""Container settings for the DoS study: production-realistic, self-contained.

PostgreSQL, not SQLite: authentic2's migrations use PG-specific index operator
classes (custom_user.0022_index_email applies `text_pattern_ops`), so SQLite fails
to migrate. The upstream deployment is Postgres too -- see poc/postgres.sh.
"""
import os
SECRET_KEY = 'dos-study-not-a-secret'
DEBUG = False                      # dev default would distort every measurement
ALLOWED_HOSTS = ['*']
A2_IDP_SAML2_ENABLE = True         # the SAML IdP endpoints under test
SAML_METADATA_AUTOLOAD = 'sp'
DATABASES = {'default': {
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': 'authentic2', 'USER': 'authentic2', 'PASSWORD': 'authentic2',
    'HOST': os.environ.get('DB_HOST', 'authentic2-db'), 'PORT': '5432',
}}

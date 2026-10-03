<?php
/* One SAML SP ("default-sp") pointing at a (forged) test IdP. The attack does
 * not need the IdP to be reachable or the signature to be valid: the O(N^2)
 * re-serialization runs while processing the inbound Response, before the
 * signature is checked. */
$config = [
    'admin' => ['core:AdminPassword'],
    'default-sp' => [
        'saml:SP',
        'entityID' => 'http://localhost:8090/module.php/saml/sp/metadata.php/default-sp',
        'idp' => 'https://idp.test/metadata',
    ],
];

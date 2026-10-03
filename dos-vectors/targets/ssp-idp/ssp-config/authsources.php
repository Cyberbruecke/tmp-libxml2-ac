<?php
/* The IdP's user-auth source. Irrelevant to the attack: the O(N^2) xmlReconciliateNs
 * runs on saveState when the AuthnRequest arrives, BEFORE the user ever logs in. */
$config = [
    'admin' => ['core:AdminPassword'],
];

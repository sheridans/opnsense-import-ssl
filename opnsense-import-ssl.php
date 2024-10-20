#!/usr/bin/env php
<?php
/*
 * Copyright (C) 2024 Sheridan Computers Limited.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

require_once "config.inc";
require_once "certs.inc";
require_once "util.inc";

// ensure running from cli
if ('cli' !== php_sapi_name()) {
    echo "This script must be run from the command line.\r\n";
    die(1);
}

// check arguments
if (4 !== $argc) {
    echo sprintf("Usage: %s <fullchain.pem> <privkey.pem> <example.com>\r\n", 
        $argv[0]
    );
    die(1);
}

// name of this script (will appear in cert description)
$cmd = end(explode('/', $argv[0]));

// simple cert verification
if (! file_exists($argv[1])) {
    echo "Certificate file not found.\r\n";
    die(1);
}

$cert = trim(file_get_contents($argv[1]));
if (! is_array(openssl_x509_parse($cert))) {
    echo "The certificate is not valid.\r\n";
    die(1);
}

// simple key verification
if (! file_exists($argv[2])) {
    echo "Private key file not found.\r\n";
    die(1);
}

$key = trim(file_get_contents($argv[2]));
if (! preg_match('/^-----BEGIN (EC )PRIVATE KEY-----(.*)-----END (EC )PRIVATE KEY-----$/s', $key)) {
    echo "The private key does not appear to be valid\r\n";
    die(1);
}

// verify private key is valid for certificate
if (! openssl_x509_check_private_key($cert, $key)) {
    echo "The private key is not valid for this certificate\r\n";
    die(1);
}

// verify issuer from allowed Let's Encrypt issuers
$allowedIssuers = [
    'O=Let\'s Encrypt, CN=E5, C=US',
    'O=Let\'s Encrypt, CN=E6, C=US',
    'O=Let\'s Encrypt, CN=R3, C=US',
    'O=Let\'s Encrypt, CN=R10, C=US',
    'O=Let\'s Encrypt, CN=R11, C=US',
];

$issuer = trim(cert_get_issuer($cert, false));
if (! in_array($issuer, $allowedIssuers)) {
    echo sprintf("The certificate issuer \"%s\" is not valid.\r\n", $issuer);
    die(1);
}

// check cert matches domain
$host = trim($argv[3]);
$subject = trim(cert_get_subject($cert, false));
if (strcmp($subject, "CN=$host") <> 0) {
    echo sprintf(
        "Certificate invalid domain '%s' specified, this certificate is for '%s'.\r\n",
        $host, ltrim($subject, 'CN=')
    );
    die(1);
}

// prepare the certificate for importing
$certData = [
    'refid' => uniqid(),
    'descr' => sprintf("Imported via opnsense-import-ssl on %s", date('Y-m-d')),
];

// populate $certData with OPNsense certificate data
cert_import($certData, $cert, $key);

// check if certificate already exists
$certRefId = null;
$certStore = &$config['cert'];
if (null !== $certStore) {
    foreach ($certStore as $existingCert) {
        if (strcmp($existingCert['crt'], $certData['crt']) === 0) {
            $certRefId = $existingCert['refid']; 
            break;
        }
    }
}

// import certificate
if (! $certRefId) {
    $certStore[] = $certData;
    $config['system']['webgui']['ssl-certref'] = $certData['refid'];

    echo "Certificate imported.\r\n";
} else {
    // exit gracefully
    echo "This certificate has already been imported.\r\n";
    die();
}

// Find expired certificates we imported
$newCertStore = [];
$expiredCerts = [];
if (null !== $certStore) {
    foreach ($certStore as $existingCert) {
        $crt = base64_decode($existingCert['crt'], true);
        if (false !== $crt) {
            $certInfo = openssl_x509_parse($crt);

            if ($certInfo['validFrom_time_t'] > time() || $certInfo['validTo_time_t'] < time()) {
                // check CN
                $cn = $certInfo['subject']['CN'] ?? null;
                if (strcmp($host, $cn) !== 0) {
                    continue;
                }

                // check description
                $searchPattern = '/^Imported via opnsense-import-ssl on [0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/';
                if (preg_match($searchPattern, $existingCert['descr'])) {
                    echo sprintf("Expired certificate: %s.\r\n", $existingCert['descr']);

                    $expiredCerts[] = $existingCert;
                } 
            } else {
                $newCertStore[] = $existingCert;
            }
        }
    }
}

// Remove expired certs we imported
if (! empty($expiredCerts)) {
    $totalCount = count($certStore);
    $expiredCount = count($expiredCerts);

    $certStore = $newCertStore;
    unset($newCertStore);

    echo sprintf("Attempted to remove %d of %d certificates (not possible if in use).\r\n", $expiredCount, $totalCount);
}
// write the config and restart the gui
write_config();
configd_run('webgui restart 2', true);

echo "Certificates updated successfully.\r\n";


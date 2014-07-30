<?php
print '<pre>';

require_once __DIR__ . '/TownsendSecurity/TownsendSecurity.php';

use TownsendSecurity\KeyService;

$key_service = new KeyService();

$server               = 'ec2-54-202-208-62.us-west-2.compute.amazonaws.com';
$port                 = 6000;
$ca_cert_file         = '../private/certs/AKMRootCACertificate.pem';
$client_cert_key_file = '../private/certs/AKMClientCertificateAndPrivateKey.pem';
$key_name             = 'AES128';
$format               = 'B64';

$key_service->addKeyServer($server, $port, $ca_cert_file, $client_cert_key_file);

$key = $key_service->getSymmetricKey($key_name, '', $format);

print_r($key);

print '</pre>';

<?php
print '<pre>';

require_once __DIR__ . '/TownsendSecurity/TownsendSecurity.php';

use TownsendSecurity\KeyService;
use TownsendSecurity\EncryptionService;

$key_service = new KeyService();

$server               = '54.91.181.5';
$failover             = '54.90.95.67';
$port                 = 6000;
$ca_cert_file         = '../private/certs/AKMRootCACertificate.pem';
$client_cert_key_file = '../private/certs/AKMClientCertificateAndPrivateKey.pem';
$key_name             = 'AES128';
$format               = 'B64';

$key_service->addKeyServer($server, $port, $ca_cert_file, $client_cert_key_file);
$key_service->addKeyServer($failover, $port, $ca_cert_file, $client_cert_key_file);

$key = $key_service->getSymmetricKey($key_name, '', $format);

print "key\n";
print_r($key);

print "\n";

$encrypt_service = new EncryptionService();
$encrypt_service->addKeyServer($server, $port, $ca_cert_file, $client_cert_key_file);
$encrypt_service->addKeyServer($failover, $port, $ca_cert_file, $client_cert_key_file);
$data = 'secret';

$r = $encrypt_service->encrypt($data, $key_name);

print_r($r);

print '</pre>';

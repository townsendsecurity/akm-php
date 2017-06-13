# Townsend Security PHP AKM Connection Library

## Example

```php
use TownsendSecurity\Akm;
use TownsendSecurity\KeyServer;

$akm = new Akm();

$key_server = new KeyServer(
    $server_name,
    $server_host,
    $path_to_local_cert,
    $path_to_ca_cert
);
$akm->addKeyServer($key_server);

$saved_key = $akm->getKeyValue('my_key');

$encrypted_data = $akm->encrypt('test data', 'my_key');
$plaintext = $akm->decrypt($encrypted_data);
assert($plaintext === 'test data');
```


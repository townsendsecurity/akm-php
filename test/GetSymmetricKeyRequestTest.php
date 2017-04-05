<?php

namespace TownsendSecurity\Test;

use PHPUnit\Framework\TestCase;

use TownsendSecurity\Akm;
use TownsendSecurity\KeyServer;
use TownsendSecurity\GetSymmetricKeyRequest;

class GetSymmetricKeyRequestTest extends TestCase
{
    /** @var TownsendSecurity\Akm */
    protected $akm;

    /** @var string */
    protected $keyname;

    public function setUp()
    {
        if (!isset(
            $_ENV['TOWNSEC_TEST_AKM_NAME'],
            $_ENV['TOWNSEC_TEST_AKM_NAME'],
            $_ENV['TOWNSEC_TEST_AKM_CERT'],
            $_ENV['TOWNSEC_TEST_AKM_CA']
        )) {
            $this->markTestSkipped('Dev AKM not available');
        }
        $name = $_ENV['TOWNSEC_TEST_AKM_NAME'];
        $host = $_ENV['TOWNSEC_TEST_AKM_HOST'];
        $local_cert = $_ENV['TOWNSEC_TEST_AKM_CERT'];
        $cafile = $_ENV['TOWNSEC_TEST_AKM_CA'];

        $keyname = isset($_ENV['TOWNSEC_TEST_AKM_KEYNAME'])
            ? $_ENV['TOWNSEC_TEST_AKM_KEYNAME']
            : 'AES256';

        $akm = new Akm();
        $akm->addKeyServer(new KeyServer(
            $name,
            $host,
            $local_cert,
            $cafile
        ));

        $this->akm = $akm;
        $this->keyname = $keyname;
    }

    public function testBasicGet()
    {
        $req = new GetSymmetricKeyRequest($this->keyname);
        $resp = $this->akm->send($req);
        $this->assertEquals(strlen($resp->getKeyValueRaw()), 32);
    }
}


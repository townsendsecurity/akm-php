<?php

namespace TownsendSecurity\Test;

use TownsendSecurity\DecryptCbcRequest;
use TownsendSecurity\EncryptCbcRequest;
use TownsendSecurity\PKCS7Padder;

class EncryptCbcRequestTest extends AkmTestCase
{
    /** @var TownsendSecurity\PaddingInterface */
    protected $p;

    public function setUp()
    {
        parent::setUp();

        $this->p = new PKCS7Padder();
    }

    /**
     * @dataProvider roundTripText
     */
    public function testEncryptionRoundTrip($text)
    {
        $iv = str_repeat('iv', 8);
        $req = new EncryptCbcRequest(
            $this->p,
            $iv,
            $this->keyname,
            '',
            $text
        );
        $resp = $this->akm->send($req);

        $req = new DecryptCbcRequest(
            $this->p,
            $iv,
            $this->keyname,
            $resp->getInstance(),
            $resp->getCipherText()
        );
        $resp = $this->akm->send($req);

        $this->assertEquals(
            $resp->getPlainText(),
            $text
        );
    }

    public function roundTripText()
    {
        $chunk_len = EncryptCbcRequest::CHUNK_LEN;
        return [
            [str_repeat('a', 15)],
            [str_repeat('a', $chunk_len + $chunk_len / 2)],
        ];
    }

    public function testConvenienceFunction()
    {
        $text = str_repeat('a', 7);
        $ciphertext = $this->akm->encrypt($text, $this->keyname);
        $this->assertEquals(
            $this->akm->decrypt($ciphertext),
            $text
        );
    }
}


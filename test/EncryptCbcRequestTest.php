<?php

namespace TownsendSecurity\Test;

use TownsendSecurity\DecryptCbcRequest;
use TownsendSecurity\EncryptCbcRequest;

class EncryptCbcRequestTest extends AkmTestCase
{
    public function testEncryptionRoundTrip()
    {
        $text = str_repeat('a', 32);

        $iv = str_repeat('iv', 8);
        $req = new EncryptCbcRequest(
            $text,
            $iv,
            $this->keyname,
            ''
        );
        $resp = $this->akm->send($req);

        $req = new DecryptCbcRequest(
            $resp->getCipherText(),
            $iv,
            '',
            $resp->getInstance()
        );
        $resp = $this->akm->send($req);

        $this->assertEquals(
            $resp->getPlainText(),
            $text
        );
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

    public function testLongPlaintextString()
    {
        $text = str_repeat('a', EncryptCbcRequest::CHUNK_LEN * 3);
        $ciphertext = $this->akm->encrypt($text, $this->keyname);
        $this->assertEquals(
            $this->akm->decrypt($ciphertext),
            $text
        );
    }
}


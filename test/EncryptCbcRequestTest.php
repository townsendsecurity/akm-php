<?php

namespace TownsendSecurity\Test;

use TownsendSecurity\DecryptCbcRequest;
use TownsendSecurity\EncryptCbcRequest;

class EncryptCbcRequestTest extends AkmTestCase
{
    /**
     * @dataProvider roundTripText
     */
    public function testEncryptionRoundTrip($text)
    {
        $iv = str_repeat('iv', 8);
        $req = new EncryptCbcRequest(
            $iv,
            $this->keyname,
            '',
            $text
        );
        $resp = $this->akm->send($req);

        $req = new DecryptCbcRequest(
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


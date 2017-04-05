<?php

namespace TownsendSecurity\Test;

use TownsendSecurity\GetSymmetricKeyRequest;

class GetSymmetricKeyRequestTest extends AkmTestCase
{
    public function testBasicGet()
    {
        $req = new GetSymmetricKeyRequest($this->keyname);
        $resp = $this->akm->send($req);
        $this->assertEquals(strlen($resp->getKeyValueRaw()), 32);
    }

    public function testFormatTranslation()
    {
        $req = new GetSymmetricKeyRequest($this->keyname, '', 'B64');
        $resp = $this->akm->send($req);
        $this->assertEquals(strlen($resp->getKeyValueRaw()), 32);
    }

    public function testConvenienceFunction()
    {
        $this->assertEquals(
            strlen($this->akm->getKeyValue($this->keyname)),
            32
        );
    }
}


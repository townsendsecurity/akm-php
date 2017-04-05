<?php

namespace TownsendSecurity\Test;

use PHPUnit\Framework\TestCase;

use TownsendSecurity\PKCS7Padder;

class PKCS7PadderTest extends TestCase
{
    /**
     * @dataProvider textProvider
     */
    public function testRoundTrip($text)
    {
        $p = new PKCS7Padder();
        $this->assertEquals(
            $p->unpad($p->pad($text)),
            $text
        );
    }

    public function textProvider()
    {
        return [
            [str_repeat('a', 7)],
            [str_repeat(chr(8), 8)],
            [str_repeat(chr(16), 16)],
        ];
    }
}


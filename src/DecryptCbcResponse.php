<?php

namespace TownsendSecurity;

class DecryptCbCResponse
{
    /** @var string */
    protected $instance;

    /** @var string */
    protected $cipherText;

    public function __construct($instance, $plain_text)
    {
        $this->instance = $instance;
        $this->plainText = $plain_text;
    }

    public function getInstance()
    {
        return $this->instance;
    }

    public function getPlainText()
    {
        return $this->plainText;
    }
}

<?php

namespace TownsendSecurity;

class EncryptCbcResponse
{
    /** @var string */
    protected $instance;

    /** @var string */
    protected $cipherText;

    public function __construct($instance, $cipher_text)
    {
        $this->instance = $instance;
        $this->cipherText = $cipher_text;
    }

    public function getInstance()
    {
        return $this->instance;
    }

    public function getCipherText()
    {
        return $this->cipherText;
    }
}

<?php

namespace TownsendSecurity;

interface RequestInterface
{
    /**
     * Gets the request type.
     *
     * @return string/
     */
    public function getType();

    /**
     * Sends this request to the stream and parses the response.
     *
     * @return mixed
     */
    public function send($stream);
}


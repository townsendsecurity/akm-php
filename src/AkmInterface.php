<?php

namespace TownsendSecurity;

interface AkmInterface
{
    /**
     * Adds a key server to this instance.
     *
     * @param TownsendSecurity\KeyServer $server
     */
    public function addKeyServer(KeyServer $server);

    /**
     * Sends a request to the AKM.
     *
     * @param TownsendSecurity\RequestInterface $request
     *
     * @return mixed Returns a response corresponding with the request sent.
     */
    public function send(RequestInterface $request);
}


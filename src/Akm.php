<?php

namespace TownsendSecurity;

use RuntimeException;

class Akm implements AkmInterface
{
    /** @var array */
    protected $servers = array();

    /**
     * {@inheritdoc}
     */
    public function addKeyServer(KeyServer $server)
    {
        $this->servers[] = $server;
    }

    /**
     * {@inheritdoc}
     */
    public function send(RequestInterface $request)
    {
        $stream = null;
        $request_type = $request->getType();
        foreach ($this->servers as $server) {
            try {
                $stream = $server->connect($request_type);
            } catch (RuntimeException $e) {
            }
            if ($stream) {
                break;
            }
        }

        if (!$stream) {
            throw new RuntimeException('Could not connect to the AKM');
        }

        return $request->send($stream);
    }
}


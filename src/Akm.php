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

    /**
     * Convenience method to get a key value.
     *
     * @param string $key_name
     * @param string $instance
     * @param string $key_format
     *
     * @return string
     */
    public function getKeyValue($key_name, $instance = '', $key_format = 'BIN')
    {
        $req = new GetSymmetricKeyRequest($key_name, $instance, $key_format);
        return $this->send($req)->getKeyValueRaw();
    }
}


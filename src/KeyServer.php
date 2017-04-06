<?php

namespace TownsendSecurity;

use RuntimeException;

class KeyServer
{
    /** @const string */
    const USER = 'user';

    /** @const string */
    const ADMIN = 'admin';

    /** @const string */
    const ENCRYPT = 'encrypt';

    /** @var string */
    protected $host;

    /** @var string */
    protected $name;

    /** @var int */
    protected $userPort = 6000;

    /** @var int */
    protected $adminPort = 6001;

    /** @var int */
    protected $encryptPort = 6003;

    /** @var resource */
    protected $ctx;

    public function __construct(
        $name,
        $host,
        $local_cert,
        $cafile,
        array $ports = []
    ) {
        $this->host = $host;
        $this->name = $name;
        $this->ctx = stream_context_create([
            'ssl' => [
                'peer_name' => $name,
                'cafile' => $cafile,
                'local_cert' => $local_cert,
            ],
        ]);
        if (isset($ports['user'])) {
            $this->userPort = $ports['user'];
        }
        if (isset($ports['admin'])) {
            $this->adminPort = $ports['admin'];
        }
        if (isset($ports['encrypt'])) {
            $this->encryptPort = $ports['encrypt'];
        }
    }

    public function getName()
    {
        return $this->name;
    }

    public function connect($srv = 'user')
    {
        switch ($srv) {
            case self::ADMIN:
                $port = $this->adminPort;
                break;
            case self::ENCRYPT:
                $port = $this->encryptPort;
                break;
            case self::USER:
            default:
                $port = $this->userPort;
                break;
        }

        $host = "tls://{$this->host}:{$port}";
        $stream = stream_socket_client(
            $host,
            $errno,
            $errstr,
            30.0,
            STREAM_CLIENT_CONNECT,
            $this->ctx
        );
        if ($stream === false) {
            throw new RuntimeException($errstr, $errno);
        }

        return $stream;
    }
}

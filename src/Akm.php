<?php

namespace TownsendSecurity;

use InvalidArgumentException;
use RuntimeException;

class Akm implements AkmInterface
{
    /** @var array */
    protected $servers = [];

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

    /**
     * Encrypts the given text, the returned string contains enough
     * information for a complete decrypt.
     *
     * @param string $text
     * @param string $key_name
     *
     * @returns string
     */
    public function encrypt($text, $key_name)
    {
        $iv = openssl_random_pseudo_bytes(16);
        $req = new EncryptCbcRequest(
            $text,
            $iv,
            $key_name,
            ''
        );
        $resp = $this->send($req);

        $iv = base64_encode($iv);
        $inst = $resp->getInstance();
        $ciphertext = base64_encode($resp->getCipherText());

        return $iv . '$' . $inst . '$' . $ciphertext;
    }

    /**
     * Decrypts data encrypted with the convenience function.
     *
     * @param string $data
     *
     * @returns string
     */
    public function decrypt($data)
    {
        $parts = explode('$', $data);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Malformed ciphertext');
        }

        $iv = base64_decode($parts[0]);
        $inst = $parts[1];
        $ciphertext = base64_decode($parts[2]);

        $req = new DecryptCbcRequest(
            $ciphertext,
            $iv,
            '',
            $inst
        );

        return $this->send($req)->getPlainText();
    }
}

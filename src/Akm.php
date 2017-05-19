<?php

namespace TownsendSecurity;

use InvalidArgumentException;
use RuntimeException;

use Defuse\Crypto\Crypto as DefuseCrypto;
use Defuse\Crypto\Key as DefuseKey;

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
        return strlen($text) > EncryptCbcRequest::CHUNK_LEN
            ? $this->encryptLong($text, $key_name)
            : $this->encryptShort($text, $key_name);
    }

    protected function encryptShort($text, $key_name)
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

        return 'S$' . $iv . '$' . $inst . '$' . $ciphertext;
    }

    protected function encryptLong($text, $key_name)
    {
        $key = DefuseKey::createNewRandomKey();
        $key_value = $key->saveToAsciiSafeString();
        $key_data = $this->encryptShort($key_value, $key_name);

        $ciphertext = DefuseCrypto::encrypt($text, $key, true);
        $ciphertext = base64_encode($ciphertext);

        return "L\n" . substr($key_data, 2) . "\n" . $ciphertext;
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
        return $data[0] === 'S'
            ? $this->decryptShort(substr($data, 2))
            : $this->decryptLong(substr($data, 2));
    }

    protected function decryptShort($data)
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

    protected function decryptLong($data)
    {
        $parts = explode("\n", $data);
        if (count($parts) !== 2) {
            throw new InvalidArgumentException('Malformed ciphertext');
        }

        $key_value = $this->decryptShort($parts[0]);
        $key = DefuseKey::loadFromAsciiSafeString($key_value, true);

        $ciphertext = base64_decode($parts[1]);

        return DefuseCrypto::decrypt($ciphertext, $key, true);
    }
}

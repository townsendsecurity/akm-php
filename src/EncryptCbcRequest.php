<?php

namespace TownsendSecurity;

use InvalidArgumentException;
use RuntimeException;

class EncryptCbcRequest implements RequestInterface
{
    /** @const string */
    const ID = '2019';

    /** @const string */
    const FMT = 'YN%s%05dYNYY%-16s%-40s%-24s';

    /** @const int */
    const CHUNK_LEN = 8080;

    /** @var string */
    protected $iv;

    /** @var string */
    protected $keyName;

    /** @var string */
    protected $instance;

    /** @var string */
    protected $data;

    /** @var string */
    protected $cipherTextFormat;

    public function __construct(
        $data,
        $iv,
        $key_name,
        $instance,
        $cipher_text_format = 'BIN'
    ) {
        if (strlen($data) > self::CHUNK_LEN) {
            throw new InvalidArgumentException(
                '"$data" must fit into one chunk of ' . self::CHUNK_LEN . ' bytes'
            );
        }

        if (strlen($key_name) > 40) {
            throw new InvalidArgumentException(
                '"$key_name" must be 40 characters or fewer'
            );
        }

        if (strlen($instance) > 24) {
            throw new InvalidArgumentException(
                '"$instance" must be 40 characters or fewer'
            );
        }

        $valid_formats = ['BIN', 'B16', 'B64'];
        if (!in_array($cipher_text_format, $valid_formats)) {
            throw new InvalidArgumentException(
                '"$cipher_text_format" must be one of "BIN", "B16", or "B64"'
            );
        }

        $this->iv = $iv;
        $this->keyName = $key_name;
        $this->instance = $instance;
        $this->data = $data;
        $this->cipherTextFormat = $cipher_text_format;
    }

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return KeyServer::ENCRYPT;
    }

    /**
     * {@inheritdoc}
     */
    public function send($stream)
    {
        $data = (new PKCS7Padder())->pad($this->data);

        $hdr = '00098' . self::ID . sprintf(
            self::FMT,
            $this->cipherTextFormat,
            strlen($data),
            $this->iv,
            $this->keyName,
            $this->instance
        );
        Util::fwriteAll($stream, $hdr . $data);

        $hdr = fread($stream, 44);

        $status = substr($hdr, 9, 4);
        if ($status !== '0000') {
            throw new RuntimeException("Got status: {$status}", (int) $status);
        }

        $cipher_text_length = (int) substr($hdr, 15, 5);
        $instance = substr($hdr, 20, 24);

        $cipher_text = fread($stream, $cipher_text_length);

        return new EncryptCbcResponse($instance, $cipher_text);
    }
}

<?php

namespace TownsendSecurity;

use InvalidArgumentException;
use RuntimeException;

class DecryptCbcRequest implements RequestInterface
{
    /** @const string */
    const ID = '2021';

    /** @const string */
    const FMT = 'YN%s%05d%s%sN%sY%s%-40s%-24s';

    /** @const string */
    const FMT_CONT = '%05d%sN%s';

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

    /** @var string */
    protected $plainTextFormat;

    public function __construct(
        $iv,
        $key_name,
        $instance,
        $data,
        $cipher_text_format = 'BIN',
        $plain_text_format = 'BIN'
    ) {
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
        if (!in_array($plain_text_format, $valid_formats)) {
            throw new InvalidArgumentException(
                '"$plain_text_format" must be one of "BIN", "B16", or "B64"'
            );
        }

        $this->iv = $iv;
        $this->keyName = $key_name;
        $this->instance = $instance;
        $this->data = $data;
        $this->cipherTextFormat = $cipher_text_format;
        $this->plainTextFormat = $plain_text_format;
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
        $chunks = str_split($this->data, self::CHUNK_LEN);

        $chunk = array_shift($chunks);
        $hdr = '00101' . self::ID . sprintf(
            self::FMT,
            $this->cipherTextFormat,
            strlen($chunk),
            $this->plainTextFormat,
            !$chunks ? 'Y' : 'N',
            !$chunks ? 'Y' : 'N',
            $this->iv,
            $this->keyName,
            $this->instance
        );
        Util::fwriteAll($stream, $hdr . $chunk);

        while ($chunk = array_shift($chunks)) {
            $hdr = sprintf(
                self::FMT_CONT,
                strlen($chunk),
                !$chunks ? 'Y' : 'N',
                !$chunks ? 'Y' : 'N'
            );
            Util::fwriteAll($stream, $hdr . $chunk);
        }

        $hdr = fread($stream, 44);

        $status = substr($hdr, 9, 4);
        if ($status !== '0000') {
            throw new RuntimeException("Got status: {$status}", (int) $status);
        }

        $end_of_response = $hdr[13];
        $plain_text_length = (int) substr($hdr, 15, 5);
        $instance = substr($hdr, 20, 24);

        $plain_text = fread($stream, $plain_text_length);

        while ($end_of_response !== 'Y') {
            $hdr = fread($stream, 11);

            $status = substr($hdr, 0, 4);
            if ($status !== '0000') {
                throw new RuntimeException(
                    "Got status: {$status}",
                    (int) $status
                );
            }

            $end_of_response = $hdr[4];
            $plain_text_length = (int) substr($hdr, 6, 5);

            $plain_text .= fread($stream, $plain_text_length);
        }

        $plain_text = (new PKCS7Padder())->unpad($plain_text);

        return new DecryptCbcResponse($instance, $plain_text);
    }
}

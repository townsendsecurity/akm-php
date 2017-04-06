<?php

namespace TownsendSecurity;

use RuntimeException;

class GetSymmetricKeyResponse
{
    /** @var array */
    protected static $keySizeLookup = [
        'BIN' => [
            128 => 16,
            192 => 24,
            256 => 32,
        ],
        'B16' => [
            128 => 32,
            192 => 48,
            256 => 64,
        ],
        'B64' => [
            128 => 24,
            192 => 32,
            256 => 44,
        ],
    ];

    /** @var string */
    protected $keyName;

    /** @var string */
    protected $instance;

    /** @var DateTime */
    protected $lastRolloverDate;

    /** @var DateTime */
    protected $expirationDate;

    /** @var int */
    protected $keySizeBits;

    /** @var string */
    protected $keyFormat;

    /** @var string */
    protected $keyValue;

    public function __construct(
        $key_name,
        $instance,
        $last_rollover_date,
        $expiration_date,
        $key_size_bits,
        $key_format,
        $key_value
    ) {
        $this->keyName = $key_name;
        $this->instance = $instance;
        $this->lastRolloverDate = $last_rollover_date;
        $this->expirationDate = $expiration_date;
        $this->keySizeBits = $key_size_bits;
        $this->keyFormat = $key_format;
        $this->keyValue = $key_value;
    }

    public function getKeyValueRaw()
    {
        $key_value = $this->getKeyValue();
        switch ($this->keyFormat) {
            case 'BIN':
                return $key_value;
            case 'B16':
                return hex2bin($key_value);
            case 'B64':
                return base64_decode($key_value);
            default:
                throw new RuntimeException('Unrecognized key format');
        }
    }

    public function getKeyValue()
    {
        $format = $this->keyFormat;
        $size = $this->keySizeBits;
        if (!isset(self::$keySizeLookup[$format][$size])) {
            throw new RuntimeException('Unknown key size');
        }

        return substr($this->keyValue, 0, self::$keySizeLookup[$format][$size]);
    }
}

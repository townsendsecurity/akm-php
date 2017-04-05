<?php

namespace TownsendSecurity;

use DateTime;
use InvalidArgumentException;
use RuntimeException;

/**
 * Gets a symmetric key.
 */
class GetSymmetricKeyRequest implements RequestInterface
{
    /** @const string */
    const ID = '2001';

    /** @const string */
    const FMT = '%-40s%-24s%s';

    /** @var string */
    protected $keyName;

    /** @var string */
    protected $instance;

    /** @var string */
    protected $keyFormat;

    public function __construct(
        $key_name = '',
        $instance = '',
        $key_format = 'BIN'
    ) {
        if (strlen($key_name . $instance) === 0) {
            throw new InvalidArgumentException(
                'one of "$key_name" or "$instance" is required'
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

        $valid_formats = array('BIN', 'B16', 'B64');
        if (!in_array($key_format, $valid_formats)) {
            throw new InvalidArgumentException(
                '"$key_format" must be one of "BIN", "B16", or "B64"'
            );
        }

        $this->keyName = $key_name;
        $this->instance = $instance;
        $this->keyFormat = $key_format;
    }

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return KeyServer::USER;
    }

    /**
     * {@inheritdoc}
     */
    public function send($stream)
    {
        Util::fwriteAll($stream, $this->getRequestData());

        $data = fread($stream, 356);

        $status = substr($data, 9, 4);
        if ($status !== '0000') {
            throw new RuntimeException("Got status: {$status}");
        }

        return new GetSymmetricKeyResponse(
            substr($data, 13, 40),                   // KeyName
            substr($data, 53, 24),                   // Instance
            Util::getDateTime(substr($data, 77, 8)), // LastRolloverDate
            Util::getDateTime(substr($data, 85, 8)), // ExpirationDate
            (int) substr($data, 93, 4),              // KeySizeBits
            substr($data, 97, 3),                    // KeyFormat
            substr($data, 100, 128)                  // KeyValue
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestData()
    {
        return '00071' . self::ID . sprintf(
            self::FMT,
            $this->keyName,
            $this->instance,
            $this->keyFormat
        );
    }
}

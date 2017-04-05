<?php

namespace TownsendSecurity;

class PKCS7Padder implements PaddingInterface
{
    /** @var int */
    protected $blockSize;

    public function __construct($block_size = 16)
    {
        $block_size = (int) $block_size;
        if ($block_size < 2 || $block_size > 255) {
            throw new InvalidArgumentException(
                'The block size must be in the range [2, 255]'
            );
        }

        $this->blockSize = $block_size;
    }

    /**
     * {@inheritdoc}
     */
    public function pad($text)
    {
        $bs = $this->blockSize;
        $n = $bs - (strlen($text) % $bs);
        if ($n === 0) {
            $n = $bs;
        }
        $c = chr($n);
        return $text . str_repeat($c, $n);
    }

    /**
     * {@inheritdoc}
     */
    public function unpad($text)
    {
        $n = ord($text[strlen($text) - 1]);
        return substr($text, 0, -$n);
    }
}


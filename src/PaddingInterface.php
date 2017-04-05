<?php

namespace TownsendSecurity;

interface PaddingInterface
{
    /**
     * Pads the given text, returning new text that can be passed to unpad,
     * resulting in the same text.
     *
     * @param string $text
     *
     * @returns string
     */
    public function pad($text);

    /**
     * Unpads text, assuming it has been passed to pad previously.
     *
     * @param string $text
     *
     * @returns string
     */
    public function unpad($text);
}


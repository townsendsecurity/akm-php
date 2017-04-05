<?php

namespace TownsendSecurity;

class Util
{
    public static function fwriteAll($stream, $data)
    {
        $len = strlen($data);
        for ($written = 0; $written < $len; $written += $ret) {
            $ret = fwrite($stream, substr($data, $written));
            if ($ret === false) {
                throw new RuntimeException('Failed to write to the AKM');
            }
        }

        return $written;
    }

    public static function getDateTime($data)
    {
        if ($data === '00000000') {
            return null;
        }
        return DateTime::createFromFormat('Ymd', $data);
    }
}


<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Support;

final class Random
{
    public static function hex(int $bytes): string
    {
        return bin2hex(random_bytes($bytes));
    }
}

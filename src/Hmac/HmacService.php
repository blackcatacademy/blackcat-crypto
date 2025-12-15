<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Hmac;

use BlackCat\Crypto\Keyring\KeyRegistry;
use Psr\Log\LoggerInterface;

final class HmacService
{
    public function __construct(private readonly KeyRegistry $registry, private readonly ?LoggerInterface $logger = null) {}

    public function sign(string $slot, string $message): string
    {
        return $this->signWithKeyId($slot, $message)['signature'];
    }

    /**
     * @return array{signature:string, keyId:string}
     */
    public function signWithKeyId(string $slot, string $message): array
    {
        $key = $this->registry->deriveAeadKey($slot);
        return [
            // DB-facing HMACs are stored in fixed-length binary columns (typically 32 bytes),
            // so we standardize on HMAC-SHA256 (32-byte output) for deterministic lookups.
            'signature' => hash_hmac('sha256', $message, $key->bytes, true),
            'keyId' => $key->id,
        ];
    }

    public function verify(string $slot, string $message, string $signature): bool
    {
        $key = $this->registry->deriveAeadKey($slot);
        $calc = hash_hmac('sha256', $message, $key->bytes, true);
        return hash_equals($calc, $signature);
    }
}

<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Config;

use BlackCat\Crypto\Config\CryptoConfig;
use PHPUnit\Framework\TestCase;

final class CryptoConfigTest extends TestCase
{
    public function testLoadsManifestSlots(): void
    {
        $manifest = tempnam(sys_get_temp_dir(), 'manifest');
        $data = [
            'slots' => [
                'core.crypto.default' => ['type' => 'aead', 'key' => 'crypto_key', 'length' => 32],
            ],
            'rotation' => [
                'core.crypto.default' => ['maxAgeSeconds' => 60],
            ],
        ];
        file_put_contents($manifest, json_encode($data));

        $keysDir = sys_get_temp_dir() . '/blackcat-keys-' . bin2hex(random_bytes(4));
        @mkdir($keysDir, 0770, true);

        $config = CryptoConfig::fromArray([
            'keys_dir' => $keysDir,
            'manifest' => $manifest,
        ]);

        $slots = $config->slots();
        self::assertArrayHasKey('core.crypto.default', $slots);
        self::assertSame('crypto_key', $slots['core.crypto.default']['key']);
        self::assertArrayHasKey('core.crypto.default', $config->rotationPolicies());
        self::assertSame($manifest, $config->manifestPath());

        @unlink($manifest);
        @rmdir($keysDir);
    }
}

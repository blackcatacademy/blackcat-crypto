<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Bridge;

use BlackCat\Crypto\Bridge\CoreCryptoBridge;
use PHPUnit\Framework\TestCase;

final class CoreCryptoBridgeTest extends TestCase
{
    private string $keysDir;
    private string $manifest;

    protected function setUp(): void
    {
        parent::setUp();
        $this->keysDir = sys_get_temp_dir() . '/blackcat-core-bridge-' . bin2hex(random_bytes(4));
        if (!is_dir($this->keysDir)) {
            mkdir($this->keysDir, 0770, true);
        }
        file_put_contents($this->keysDir . '/crypto_key_v1.key', random_bytes(32));
        file_put_contents($this->keysDir . '/crypto_legacy_v1.key', random_bytes(32));

        $this->manifest = tempnam(sys_get_temp_dir(), 'core-manifest-') ?: ($this->keysDir . '/manifest.json');
        $data = [
            'slots' => [
                'core.crypto.default' => ['type' => 'aead', 'key' => 'crypto_key', 'length' => 32],
                'core.crypto.legacy' => ['type' => 'aead', 'key' => 'crypto_legacy', 'length' => 32],
            ],
        ];
        file_put_contents($this->manifest, json_encode($data));

        CoreCryptoBridge::configure([
            'keys_dir' => $this->keysDir,
            'manifest' => $this->manifest,
        ]);
        CoreCryptoBridge::boot();
    }

    protected function tearDown(): void
    {
        CoreCryptoBridge::flush();
        if (is_dir($this->keysDir)) {
            foreach (glob($this->keysDir . '/*') as $file) {
                @unlink($file);
            }
            @rmdir($this->keysDir);
        }
        if (isset($this->manifest) && is_file($this->manifest)) {
            @unlink($this->manifest);
        }
        parent::tearDown();
    }

    public function testEncryptAndDecryptBinary(): void
    {
        $cipher = CoreCryptoBridge::encryptBinary('crypto.default', 'secret-data');
        self::assertNotSame('secret-data', $cipher);
        $plain = CoreCryptoBridge::decryptBinary('crypto.default', $cipher);
        self::assertSame('secret-data', $plain);
    }

    public function testDecryptsLegacyPayloadWithoutKeyId(): void
    {
        $binary = CoreCryptoBridge::encryptBinary('crypto.legacy', 'legacy-secret');
        $ptr = 0;
        $version = ord($binary[$ptr++]);
        self::assertSame(2, $version);
        $keyLen = ord($binary[$ptr++]);
        $ptr += $keyLen;
        $nonceLen = ord($binary[$ptr++]);
        $nonce = substr($binary, $ptr, $nonceLen);
        $ptr += $nonceLen;
        $ciphertext = substr($binary, $ptr);
        $legacyPayload = chr(1) . chr($nonceLen) . $nonce . $ciphertext;

        $plain = CoreCryptoBridge::decryptBinary('crypto.legacy', $legacyPayload);
        self::assertSame('legacy-secret', $plain);
    }

    public function testExposesKeyMaterial(): void
    {
        $material = CoreCryptoBridge::deriveKeyMaterial('crypto.default');
        self::assertSame('core.crypto.default', $material['slot']);
        $all = CoreCryptoBridge::listKeyMaterial('crypto.default');
        self::assertNotEmpty($all);
    }
}

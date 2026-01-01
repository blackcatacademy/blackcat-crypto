<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Bootstrap;

use BlackCat\Crypto\Bootstrap\PlatformBootstrap;
use PHPUnit\Framework\TestCase;

final class PlatformBootstrapTest extends TestCase
{
    private string $keysDir;
    private string $manifestPath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->keysDir = sys_get_temp_dir() . '/blackcat-bootstrap-' . bin2hex(random_bytes(4));
        if (!is_dir($this->keysDir)) {
            mkdir($this->keysDir, 0770, true);
        }

        file_put_contents($this->keysDir . '/users.pii_v1.key', random_bytes(32));

        $this->manifestPath = tempnam(sys_get_temp_dir(), 'blackcat-manifest-') ?: ($this->keysDir . '/manifest.json');
        $manifest = [
            'slots' => [
                'users.pii' => ['type' => 'aead', 'key' => 'users.pii', 'length' => 32],
            ],
        ];
        file_put_contents($this->manifestPath, json_encode($manifest));
    }

    protected function tearDown(): void
    {
        if (isset($this->keysDir) && is_dir($this->keysDir)) {
            foreach (glob($this->keysDir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($this->keysDir);
        }
        if (isset($this->manifestPath) && is_file($this->manifestPath)) {
            @unlink($this->manifestPath);
        }

        parent::tearDown();
    }

    public function testBootsCryptoManagerFromExplicitOptions(): void
    {
        $crypto = PlatformBootstrap::boot([
            'keys_dir' => $this->keysDir,
            'manifest' => $this->manifestPath,
            'init_core' => false,
            'init_database' => false,
        ]);

        $envelope = $crypto->encryptContext('users.pii', 'secret');
        $plain = $crypto->decryptContext('users.pii', $envelope->encode());

        self::assertSame('secret', $plain);
    }
}

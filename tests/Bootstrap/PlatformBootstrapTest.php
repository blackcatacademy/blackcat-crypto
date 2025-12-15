<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Bootstrap;

use BlackCat\Crypto\Bootstrap\PlatformBootstrap;
use PHPUnit\Framework\TestCase;

final class PlatformBootstrapTest extends TestCase
{
    private string $keysDir;
    private string $manifestPath;
    /** @var array<string,string|null> */
    private array $previousEnv = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->previousEnv = [
            'BLACKCAT_KEYS_DIR' => getenv('BLACKCAT_KEYS_DIR') !== false ? (string)getenv('BLACKCAT_KEYS_DIR') : null,
            'APP_KEYS_DIR' => getenv('APP_KEYS_DIR') !== false ? (string)getenv('APP_KEYS_DIR') : null,
            'BLACKCAT_CRYPTO_MANIFEST' => getenv('BLACKCAT_CRYPTO_MANIFEST') !== false ? (string)getenv('BLACKCAT_CRYPTO_MANIFEST') : null,
        ];

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

        $this->setEnv('BLACKCAT_KEYS_DIR', $this->keysDir);
        $this->setEnv('BLACKCAT_CRYPTO_MANIFEST', $this->manifestPath);
    }

    protected function tearDown(): void
    {
        $this->restoreEnv();

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

    public function testBootsCryptoManagerFromEnv(): void
    {
        $crypto = PlatformBootstrap::boot([
            'init_core' => false,
            'init_database' => false,
        ]);

        $envelope = $crypto->encryptContext('users.pii', 'secret');
        $plain = $crypto->decryptContext('users.pii', $envelope->encode());

        self::assertSame('secret', $plain);
    }

    private function setEnv(string $key, string $value): void
    {
        putenv($key . '=' . $value);
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
    }

    private function restoreEnv(): void
    {
        foreach ($this->previousEnv as $key => $value) {
            if ($value === null) {
                putenv($key);
                unset($_ENV[$key], $_SERVER[$key]);
                continue;
            }
            $this->setEnv($key, $value);
        }
    }
}


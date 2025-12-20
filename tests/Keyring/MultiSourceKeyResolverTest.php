<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Keyring;

use BlackCat\Crypto\Keyring\KeySlot;
use BlackCat\Crypto\Keyring\MultiSourceKeyResolver;
use PHPUnit\Framework\TestCase;

final class MultiSourceKeyResolverTest extends TestCase
{
    private string $tmpDir;
    /** @var array<string,string|null> */
    private array $previousEnv = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->tmpDir = sys_get_temp_dir() . '/blackcat-keys-' . bin2hex(random_bytes(4));
        if (!is_dir($this->tmpDir)) {
            mkdir($this->tmpDir, 0770, true);
        }

        $this->previousEnv = [
            'BC_KEY_CRYPTO_KEY_V3' => getenv('BC_KEY_CRYPTO_KEY_V3') !== false ? (string)getenv('BC_KEY_CRYPTO_KEY_V3') : null,
        ];
    }

    protected function tearDown(): void
    {
        foreach ($this->previousEnv as $key => $value) {
            if ($value === null) {
                putenv($key);
                unset($_ENV[$key], $_SERVER[$key]);
                continue;
            }
            $this->setEnv($key, $value);
        }

        if (isset($this->tmpDir) && is_dir($this->tmpDir)) {
            foreach (glob($this->tmpDir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($this->tmpDir);
        }

        parent::tearDown();
    }

    public function testLoadsHexAndBase64KeyFilesAndKeepsCanonicalId(): void
    {
        $slot = KeySlot::fromArray('users.pii', [
            'type' => 'aead',
            'key' => 'crypto_key',
            'length' => 32,
        ]);

        $v1 = random_bytes(32);
        file_put_contents($this->tmpDir . '/crypto_key_v1.hex', bin2hex($v1) . "\n");

        $v2 = random_bytes(32);
        file_put_contents($this->tmpDir . '/crypto_key_v2.b64', base64_encode($v2) . "\n");

        $resolver = new MultiSourceKeyResolver([
            ['type' => 'filesystem', 'path' => $this->tmpDir],
        ]);

        $mat = $resolver->resolve($slot);
        self::assertSame('crypto_key_v2.key', $mat->id);
        self::assertSame($v2, $mat->bytes);

        $all = $resolver->all($slot);
        self::assertCount(2, $all);
        self::assertSame(['crypto_key_v1.key', 'crypto_key_v2.key'], array_map(static fn($m) => $m->id, $all));
    }

    public function testLoadsEnvKeysAsBase64AndValidatesLength(): void
    {
        $slot = KeySlot::fromArray('users.pii', [
            'type' => 'aead',
            'key' => 'crypto_key',
            'length' => 32,
        ]);

        $bytes = random_bytes(32);
        $this->setEnv('BC_KEY_CRYPTO_KEY_V3', base64_encode($bytes));

        $resolver = new MultiSourceKeyResolver([
            ['type' => 'env', 'prefix' => 'BC_KEY_'],
        ]);

        $mat = $resolver->resolve($slot);
        self::assertSame('crypto_key_v3.key', $mat->id);
        self::assertSame($bytes, $mat->bytes);
    }

    public function testDoesNotFallBackToUnrelatedSingleKeyFile(): void
    {
        $slot = KeySlot::fromArray('users.pii', [
            'type' => 'aead',
            'key' => 'crypto_key',
            'length' => 32,
        ]);

        file_put_contents($this->tmpDir . '/unrelated_key_v1.key', random_bytes(32));

        $resolver = new MultiSourceKeyResolver([
            ['type' => 'filesystem', 'path' => $this->tmpDir],
        ]);

        $this->expectException(\RuntimeException::class);
        $resolver->resolve($slot);
    }

    private function setEnv(string $key, string $value): void
    {
        putenv($key . '=' . $value);
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
    }
}

<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\KeysLintCommand;
use PHPUnit\Framework\TestCase;

final class KeysLintCommandTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/bcat-keys-lint-' . bin2hex(random_bytes(4));
        @mkdir($this->tmp, 0770, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tmp)) {
            foreach (glob($this->tmp . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($this->tmp);
        }
    }

    public function testReportsOkForValidKeys(): void
    {
        $manifestPath = $this->tmp . '/manifest.json';
        file_put_contents($manifestPath, json_encode([
            'slots' => [
                'core.crypto.default' => ['type' => 'aead', 'key' => 'crypto_key', 'length' => 32],
                'core.hmac.email' => ['type' => 'hmac', 'key' => 'email_hash_key', 'length' => 64],
            ],
        ]));

        $keysDir = $this->tmp . '/keys';
        @mkdir($keysDir, 0770, true);
        file_put_contents($keysDir . '/crypto_key_v1.key', random_bytes(32));
        file_put_contents($keysDir . '/email_hash_key_v1.key', random_bytes(64));

        $cmd = new KeysLintCommand();
        ob_start();
        $code = $cmd->run(["--manifest={$manifestPath}", "--keys-dir={$keysDir}", '--json']);
        $out = (string)ob_get_clean();

        self::assertSame(0, $code);
        $decoded = json_decode($out, true);
        self::assertIsArray($decoded);
        self::assertTrue($decoded['ok']);
        self::assertSame([], $decoded['errors']);
    }

    public function testReportsErrorWhenSlotHasNoKeyFiles(): void
    {
        $manifestPath = $this->tmp . '/manifest.json';
        file_put_contents($manifestPath, json_encode([
            'slots' => [
                'core.crypto.default' => ['type' => 'aead', 'key' => 'crypto_key', 'length' => 32],
                'core.hmac.email' => ['type' => 'hmac', 'key' => 'email_hash_key', 'length' => 64],
            ],
        ]));

        $keysDir = $this->tmp . '/keys';
        @mkdir($keysDir, 0770, true);
        file_put_contents($keysDir . '/crypto_key_v1.key', random_bytes(32));

        $cmd = new KeysLintCommand();
        ob_start();
        $code = $cmd->run(["--manifest={$manifestPath}", "--keys-dir={$keysDir}", '--json']);
        $out = (string)ob_get_clean();

        self::assertSame(1, $code);
        $decoded = json_decode($out, true);
        self::assertIsArray($decoded);
        self::assertFalse($decoded['ok']);
        self::assertNotEmpty($decoded['errors']);
    }
}


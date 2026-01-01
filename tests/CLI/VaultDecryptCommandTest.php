<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\VaultDecryptCommand;
use BlackCat\Crypto\Bridge\CoreCryptoBridge;
use PHPUnit\Framework\TestCase;

final class VaultDecryptCommandTest extends TestCase
{
    private string $keysDir;
    private string $manifest;

    protected function setUp(): void
    {
        parent::setUp();
        $this->keysDir = sys_get_temp_dir() . '/vault-decrypt-' . bin2hex(random_bytes(4));
        mkdir($this->keysDir, 0770, true);
        file_put_contents($this->keysDir . '/filevault_key_v1.key', random_bytes(32));

        $this->manifest = tempnam(sys_get_temp_dir(), 'manifest');
        file_put_contents($this->manifest, json_encode([
            'slots' => ['core.vault' => ['type' => 'aead', 'key' => 'filevault_key']],
        ]));

        CoreCryptoBridge::configure([
            'keys_dir' => $this->keysDir,
            'manifest' => $this->manifest,
        ]);
        CoreCryptoBridge::boot();
    }

    protected function tearDown(): void
    {
        CoreCryptoBridge::flush();
        foreach (glob($this->keysDir . '/*') as $file) {
            @unlink($file);
        }
        @rmdir($this->keysDir);
        if (is_file($this->manifest)) {
            @unlink($this->manifest);
        }
        parent::tearDown();
    }

    public function testDecryptsSinglePayload(): void
    {
        $plain = 'sensitive payload';
        $encPath = tempnam(sys_get_temp_dir(), 'payload') . '.enc';
        file_put_contents($encPath, $this->buildSinglePayload($plain));

        $command = new VaultDecryptCommand();
        ob_start();
        $exitCode = $command->run([$encPath]);
        $output = ob_get_clean();

        self::assertSame(0, $exitCode);
        self::assertSame($plain, $output);

        @unlink($encPath);
    }

    private function buildSinglePayload(string $plaintext): string
    {
        $key = file_get_contents($this->keysDir . '/filevault_key_v1.key');
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, '', $nonce, $key);
        $tag = substr($cipher, -SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
        $body = substr($cipher, 0, -SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);

        return chr(2)
            . chr(strlen('v1')) . 'v1'
            . chr(strlen($nonce)) . $nonce
            . chr(strlen($tag)) . $tag
            . $body;
    }
}

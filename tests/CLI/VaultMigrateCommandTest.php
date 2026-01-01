<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\VaultMigrateCommand;
use BlackCat\Crypto\Bridge\CoreCryptoBridge;
use PHPUnit\Framework\TestCase;

final class VaultMigrateCommandTest extends TestCase
{
    private string $keysDir;
    private string $manifest;
    private string $tmpDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tmpDir = sys_get_temp_dir() . '/crypto-cli-' . bin2hex(random_bytes(4));
        mkdir($this->tmpDir, 0770, true);
        $this->keysDir = $this->tmpDir . '/keys';
        mkdir($this->keysDir, 0770, true);
        file_put_contents($this->keysDir . '/filevault_key_v1.key', random_bytes(32));

        $this->manifest = $this->tmpDir . '/manifest.json';
        file_put_contents($this->manifest, json_encode([
            'slots' => [
                'core.vault' => ['type' => 'aead', 'key' => 'filevault_key', 'length' => 32],
            ],
        ]));

        CoreCryptoBridge::configure([
            'keys_dir' => $this->keysDir,
            'manifest' => $this->manifest,
        ]);
    }

    protected function tearDown(): void
    {
        CoreCryptoBridge::flush();
        if (is_dir($this->tmpDir)) {
            $files = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($this->tmpDir, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($files as $file) {
                $file->isDir() ? @rmdir($file->getRealPath()) : @unlink($file->getRealPath());
            }
            @rmdir($this->tmpDir);
        }
        parent::tearDown();
    }

    public function testMigratesSinglePayload(): void
    {
        $plain = 'hello-secret';
        $legacy = $this->tmpDir . '/single.enc';
        file_put_contents($legacy, $this->buildSinglePayload($plain));

        $dest = $this->tmpDir . '/envelope.b64';
        $command = new VaultMigrateCommand();
        $exitCode = $command->run([$legacy, $dest]);
        self::assertSame(0, $exitCode);

        $manager = CoreCryptoBridge::boot();
        $decoded = $manager->decryptContext('core.vault', file_get_contents($dest));
        self::assertSame($plain, $decoded);
    }

    public function testMigratesStreamPayload(): void
    {
        $plain = str_repeat('A', 1024 * 64);
        $legacy = $this->tmpDir . '/stream.enc';
        file_put_contents($legacy, $this->buildStreamPayload($plain));

        $dest = $this->tmpDir . '/stream-envelope.b64';
        $command = new VaultMigrateCommand();
        $exitCode = $command->run([$legacy, $dest]);
        self::assertSame(0, $exitCode);

        $manager = CoreCryptoBridge::boot();
        $decoded = $manager->decryptContext('core.vault', file_get_contents($dest));
        self::assertSame($plain, $decoded);
    }

    private function buildSinglePayload(string $plaintext): string
    {
        $key = file_get_contents($this->keysDir . '/filevault_key_v1.key');
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, '', $nonce, $key);
        $tag = substr($cipher, -SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
        $body = substr($cipher, 0, -SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);

        $payload = chr(2);
        $payload .= chr(strlen('v1')) . 'v1';
        $payload .= chr(strlen($nonce)) . $nonce;
        $payload .= chr(strlen($tag)) . $tag;
        $payload .= $body;
        return $payload;
    }

    private function buildStreamPayload(string $plaintext): string
    {
        $key = file_get_contents($this->keysDir . '/filevault_key_v1.key');
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $payload = chr(2);
        $payload .= chr(strlen('v1')) . 'v1';
        $payload .= chr(strlen($header)) . $header;
        $payload .= chr(0); // tag len 0 => stream

        $ptr = 0;
        $len = strlen($plaintext);
        while ($ptr < $len) {
            $chunk = substr($plaintext, $ptr, 1024);
            $ptr += strlen($chunk);
            $tag = $ptr >= $len ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
            $frame = sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag);
            $payload .= pack('N', strlen($frame)) . $frame;
        }

        return $payload;
    }
}

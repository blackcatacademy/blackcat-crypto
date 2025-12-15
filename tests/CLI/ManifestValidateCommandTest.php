<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\ManifestValidateCommand;
use PHPUnit\Framework\TestCase;

final class ManifestValidateCommandTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/bcat-manifest-' . bin2hex(random_bytes(4));
        @mkdir($this->tmp);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tmp . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->tmp);
    }

    public function testInvalidManifest(): void
    {
        $path = $this->tmp . '/bad.json';
        file_put_contents($path, '{ this-is-not-json }');

        $cmd = new ManifestValidateCommand();
        ob_start();
        $code = $cmd->run([$path]);
        ob_end_clean();

        self::assertSame(1, $code);
    }

    public function testValidManifest(): void
    {
        $path = $this->tmp . '/good.json';
        $manifest = [
            'slots' => [
                'core.crypto.default' => [
                    'type' => 'aead',
                    'key' => 'crypto_key',
                    'length' => 32,
                ],
                'core.hmac.email' => [
                    'type' => 'hmac',
                    'key' => 'email_hash_key',
                    'length' => 64,
                ],
            ],
            'rotation' => [
                'core.crypto.default' => ['maxAgeSeconds' => 3600],
            ],
        ];
        file_put_contents($path, json_encode($manifest));

        $cmd = new ManifestValidateCommand();
        ob_start();
        $code = $cmd->run([$path, '--json']);
        $output = (string)ob_get_clean();

        self::assertSame(0, $code);
        $decoded = json_decode($output, true);
        self::assertIsArray($decoded);
        self::assertTrue($decoded['valid']);
        self::assertSame([], $decoded['issues']);
    }
}

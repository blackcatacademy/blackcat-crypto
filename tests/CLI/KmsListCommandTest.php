<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\KmsListCommand;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class KmsListCommandTest extends TestCase
{
    public function testListsEndpointsAsText(): void
    {
        [$configPath, $tmpDir] = $this->makeRuntimeConfig('a=http://localhost:7001,b=http://localhost:7002');
        $cmd = new KmsListCommand(new NullLogger());

        ob_start();
        $code = $cmd->run(['--config=' . $configPath]);
        $out = ob_get_clean();

        self::assertSame(0, $code);
        self::assertStringContainsString('KMS clients:', $out);
        self::assertStringContainsString('a (type=http', $out);
        self::assertStringContainsString('b (type=http', $out);

        $this->cleanupTmp($tmpDir);
    }

    public function testListsEndpointsAsJson(): void
    {
        [$configPath, $tmpDir] = $this->makeRuntimeConfig('primary=http://localhost:9000');
        $cmd = new KmsListCommand(new NullLogger());

        ob_start();
        $code = $cmd->run(['--config=' . $configPath, '--json']);
        $out = ob_get_clean();

        self::assertSame(0, $code);
        $decoded = json_decode($out, true);
        self::assertIsArray($decoded);
        self::assertSame('primary', $decoded[0]['id'] ?? null);
        self::assertSame('http', $decoded[0]['type'] ?? null);

        $this->cleanupTmp($tmpDir);
    }

    public function testFailsWithoutEndpoints(): void
    {
        [$configPath, $tmpDir] = $this->makeRuntimeConfig('');
        $cmd = new KmsListCommand(new NullLogger());

        ob_start();
        $code = $cmd->run(['--config=' . $configPath]);
        ob_end_clean();

        self::assertSame(1, $code);

        $this->cleanupTmp($tmpDir);
    }

    /**
     * @return array{0:string,1:string}
     */
    private function makeRuntimeConfig(string $kmsEndpoints): array
    {
        $tmpDir = sys_get_temp_dir() . '/bcat-kms-' . bin2hex(random_bytes(4));
        @mkdir($tmpDir, 0700, true);
        @chmod($tmpDir, 0700);

        $keysDir = $tmpDir . '/keys';
        @mkdir($keysDir, 0700, true);
        @chmod($keysDir, 0700);
        file_put_contents($keysDir . '/dummy_v1.key', random_bytes(32));

        $cfg = [
            'crypto' => [
                'keys_dir' => $keysDir,
            ],
        ];
        if ($kmsEndpoints !== '') {
            $cfg['crypto']['kms_endpoints'] = $kmsEndpoints;
        }

        $path = $tmpDir . '/config.runtime.json';
        file_put_contents($path, json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        @chmod($path, 0600);

        return [$path, $tmpDir];
    }

    private function cleanupTmp(string $tmpDir): void
    {
        if (!is_dir($tmpDir)) {
            return;
        }

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($tmpDir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($files as $file) {
            $file->isDir() ? @rmdir($file->getRealPath()) : @unlink($file->getRealPath());
        }
        @rmdir($tmpDir);
    }
}

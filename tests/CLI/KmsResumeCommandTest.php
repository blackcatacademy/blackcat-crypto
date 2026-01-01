<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\KmsResumeCommand;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class KmsResumeCommandTest extends TestCase
{
    public function testResumesClient(): void
    {
        [$configPath, $tmpDir] = $this->makeRuntimeConfig('a=http://localhost:7001');
        $cmd = new KmsResumeCommand(new NullLogger());
        ob_start();
        $code = $cmd->run(['--config=' . $configPath, 'a']);
        $out = ob_get_clean();

        self::assertSame(0, $code);
        self::assertStringContainsString('Resumed a', $out);

        $this->cleanupTmp($tmpDir);
    }

    public function testFailsWithBadArgs(): void
    {
        $cmd = new KmsResumeCommand(new NullLogger());
        ob_start();
        $code = $cmd->run([]);
        ob_end_clean();

        self::assertSame(1, $code);
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
                'kms_endpoints' => $kmsEndpoints,
            ],
        ];

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

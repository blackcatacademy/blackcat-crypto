<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\KeyRotateCommand;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class KeyRotateCommandTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/bcat-key-rotate-' . bin2hex(random_bytes(4));
        @mkdir($this->tmpDir, 0770, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tmpDir)) {
            foreach (glob($this->tmpDir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($this->tmpDir);
        }
    }

    public function testFailsWhenArgsMissing(): void
    {
        $cmd = new KeyRotateCommand(new NullLogger());
        ob_start();
        $code = $cmd->run([]);
        ob_end_clean();

        self::assertSame(1, $code);
        self::assertSame([], glob($this->tmpDir . '/*') ?: []);
    }

    public function testGeneratesKeyFile(): void
    {
        $cmd = new KeyRotateCommand(new NullLogger());
        ob_start();
        $code = $cmd->run(['tenant-01', $this->tmpDir, '--length=40']);
        $output = ob_get_clean();

        self::assertSame(0, $code);
        $files = glob($this->tmpDir . '/*.key');
        self::assertNotEmpty($files, 'Expected generated key file');
        $generated = (string)$files[0];
        self::assertStringContainsString('tenant-01', $generated);
        self::assertGreaterThanOrEqual(40, filesize($generated) ?: 0);
        self::assertStringContainsString('Rotated tenant-01', $output);
    }
}

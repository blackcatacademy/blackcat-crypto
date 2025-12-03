<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\VaultDiagCommand;
use PHPUnit\Framework\TestCase;

final class VaultDiagCommandTest extends TestCase
{
    public function testInspectsDirectory(): void
    {
        $dir = sys_get_temp_dir() . '/vault-diag-' . bin2hex(random_bytes(4));
        mkdir($dir, 0770, true);
        file_put_contents($dir . '/sample.enc', $this->buildPayload());
        file_put_contents($dir . '/sample.enc.meta', json_encode([
            'key_version' => 'v1',
            'context' => 'core.vault',
        ]));

        $command = new VaultDiagCommand();
        ob_start();
        $exitCode = $command->run([$dir]);
        $output = ob_get_clean();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('sample.enc', $output);
        self::assertStringContainsString('Summary: 1 ok', $output);

        foreach (glob($dir . '/*') as $file) {
            @unlink($file);
        }
        @rmdir($dir);
    }

    public function testJsonOutputAndWarnings(): void
    {
        $dir = sys_get_temp_dir() . '/vault-diag-' . bin2hex(random_bytes(4));
        mkdir($dir, 0770, true);
        $file = $dir . '/warn.enc';
        file_put_contents($file, $this->buildPayload());
        file_put_contents($file . '.meta', json_encode(['key_version' => 'v1']));

        $manifest = tempnam(sys_get_temp_dir(), 'manifest');
        file_put_contents($manifest, json_encode(['slots' => ['core.vault' => []]]));

        $command = new VaultDiagCommand();
        ob_start();
        $exitCode = $command->run(['--json', '--manifest=' . $manifest, '--fail-on-warn', $dir]);
        $json = ob_get_clean();

        $decoded = json_decode($json, true);
        self::assertNotNull($decoded);
        self::assertSame(2, $exitCode);
        self::assertSame(1, $decoded['summary']['warnings']);

        foreach (glob($dir . '/*') as $file) {
            @unlink($file);
        }
        @rmdir($dir);
        @unlink($manifest);
    }

    private function buildPayload(): string
    {
        $nonce = random_bytes(24);
        $tag = random_bytes(16);
        $cipher = random_bytes(32);
        return chr(2)
            . chr(strlen('v1')) . 'v1'
            . chr(strlen($nonce)) . $nonce
            . chr(strlen($tag)) . $tag
            . $cipher;
    }
}

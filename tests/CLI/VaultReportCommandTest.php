<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\VaultReportCommand;
use PHPUnit\Framework\TestCase;

final class VaultReportCommandTest extends TestCase
{
    public function testReportsContexts(): void
    {
        $dir = sys_get_temp_dir() . '/vault-report-' . bin2hex(random_bytes(4));
        mkdir($dir, 0770, true);
        file_put_contents($dir . '/file1.enc', random_bytes(32));
        file_put_contents($dir . '/file1.enc.meta', json_encode([
            'context' => 'core.vault',
            'key_version' => 'v1',
        ]));
        file_put_contents($dir . '/file2.enc', random_bytes(32));
        file_put_contents($dir . '/file2.enc.meta', json_encode([
            'context' => 'core.vault',
            'key_version' => 'v2',
        ]));

        $command = new VaultReportCommand();
        ob_start();
        $exit = $command->run([$dir]);
        $output = ob_get_clean();

        self::assertSame(0, $exit);
        self::assertStringContainsString('core.vault', $output);
        self::assertStringContainsString('Key versions', $output);

        foreach (glob($dir . '/*') as $file) {
            @unlink($file);
        }
        @rmdir($dir);
    }

    public function testManifestCoverage(): void
    {
        $dir = sys_get_temp_dir() . '/vault-report-' . bin2hex(random_bytes(4));
        mkdir($dir, 0770, true);
        file_put_contents($dir . '/file1.enc', random_bytes(32));
        file_put_contents($dir . '/file1.enc.meta', json_encode([
            'context' => 'core.vault',
            'key_version' => 'v1',
        ]));
        $manifest = tempnam(sys_get_temp_dir(), 'manifest');
        file_put_contents($manifest, json_encode(['slots' => [
            'core.vault' => ['type' => 'aead'],
            'unused.context' => ['type' => 'aead'],
        ]]));

        $command = new VaultReportCommand();
        ob_start();
        $exit = $command->run(["--manifest={$manifest}", $dir]);
        $output = ob_get_clean();

        self::assertSame(0, $exit);
        self::assertStringContainsString('unused.context', $output);
        $command = new VaultReportCommand();
        $exit = $command->run(["--manifest={$manifest}", "--json", "--fail-on-unused", $dir]);
        self::assertSame(2, $exit);

        foreach (glob($dir . '/*') as $file) {
            @unlink($file);
        }
        @rmdir($dir);
        @unlink($manifest);
    }

    public function testFailOnMissingMeta(): void
    {
        $dir = sys_get_temp_dir() . '/vault-report-' . bin2hex(random_bytes(4));
        mkdir($dir, 0770, true);
        file_put_contents($dir . '/orphan.enc', random_bytes(32));

        $command = new VaultReportCommand();
        ob_start();
        $exit = $command->run(["--fail-on-missing", $dir]);
        $output = ob_get_clean();

        self::assertSame(3, $exit);
        self::assertStringContainsString('Missing metadata', $output);

        $command = new VaultReportCommand();
        ob_start();
        $command->run(["--json", "--trace", $dir]);
        $json = ob_get_clean();
        $decoded = json_decode($json, true);
        self::assertIsArray($decoded);
        self::assertSame(1, $decoded['missing_meta']);
        self::assertNotEmpty($decoded['trace']);
        self::assertTrue($decoded['trace'][0]['missing_meta']);

        foreach (glob($dir . '/*') as $file) {
            @unlink($file);
        }
        @rmdir($dir);
    }
}

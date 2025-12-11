<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\ManifestDiffCommand;
use PHPUnit\Framework\TestCase;

final class ManifestDiffCommandTest extends TestCase
{
    public function testReportsDifferences(): void
    {
        $from = tempnam(sys_get_temp_dir(), 'manifest-from');
        $to = tempnam(sys_get_temp_dir(), 'manifest-to');

        file_put_contents($from, json_encode([
            'slots' => [
                'core.vault' => ['type' => 'aead', 'key' => 'filevault_key'],
                'core.hmac.email' => ['type' => 'hmac', 'key' => 'email_key'],
            ],
            'rotation' => [
                'core.vault' => ['maxAgeSeconds' => 60],
            ],
        ]));

        file_put_contents($to, json_encode([
            'slots' => [
                'core.vault' => ['type' => 'aead', 'key' => 'filevault_key_v2'],
                'core.crypto.default' => ['type' => 'aead', 'key' => 'crypto_key'],
            ],
            'rotation' => [
                'core.crypto.default' => ['maxAgeSeconds' => 120],
            ],
        ]));

        $command = new ManifestDiffCommand();
        ob_start();
        $exit = $command->run(["--from={$from}", "--to={$to}"]);
        $output = ob_get_clean();

        self::assertSame(2, $exit);
        self::assertStringContainsString('SLOTS_ONLY_IN_FROM', strtoupper($output));

        @unlink($from);
        @unlink($to);
    }
}

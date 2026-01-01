<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\ManifestShowCommand;
use PHPUnit\Framework\TestCase;

final class ManifestShowCommandTest extends TestCase
{
    public function testExportsManifest(): void
    {
        $manifest = tempnam(sys_get_temp_dir(), 'manifest');
        file_put_contents($manifest, json_encode([
            'slots' => ['core.vault' => ['type' => 'aead', 'key' => 'filevault_key']],
            'rotation' => [],
        ]));

        $output = tempnam(sys_get_temp_dir(), 'manifest-out');

        $command = new ManifestShowCommand();
        $exit = $command->run(['--manifest=' . $manifest, '--output=' . $output]);

        self::assertSame(0, $exit);
        $json = json_decode(file_get_contents($output), true);
        self::assertSame($manifest, $json['manifest']);
        self::assertArrayHasKey('core.vault', $json['slots']);

        @unlink($manifest);
        @unlink($output);
    }
}

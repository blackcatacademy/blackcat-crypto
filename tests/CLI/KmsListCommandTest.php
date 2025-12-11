<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\KmsListCommand;
use BlackCat\Crypto\Kms\KmsRouter;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class KmsListCommandTest extends TestCase
{
    private string $envBackup = '';

    protected function setUp(): void
    {
        $this->envBackup = getenv('BLACKCAT_KMS_ENDPOINTS') ?: '';
    }

    protected function tearDown(): void
    {
        putenv('BLACKCAT_KMS_ENDPOINTS=' . $this->envBackup);
    }

    public function testListsEndpointsAsText(): void
    {
        putenv('BLACKCAT_KMS_ENDPOINTS=a=http://localhost:7001,b=http://localhost:7002');
        $cmd = new KmsListCommand(new NullLogger());

        ob_start();
        $code = $cmd->run([]);
        $out = ob_get_clean();

        self::assertSame(0, $code);
        self::assertStringContainsString('KMS clients:', $out);
        self::assertStringContainsString('a (type=http', $out);
        self::assertStringContainsString('b (type=http', $out);
    }

    public function testListsEndpointsAsJson(): void
    {
        putenv('BLACKCAT_KMS_ENDPOINTS=primary=http://localhost:9000');
        $cmd = new KmsListCommand(new NullLogger());

        ob_start();
        $code = $cmd->run(['--json']);
        $out = ob_get_clean();

        self::assertSame(0, $code);
        $decoded = json_decode($out, true);
        self::assertIsArray($decoded);
        self::assertSame('primary', $decoded[0]['id'] ?? null);
        self::assertSame('http', $decoded[0]['type'] ?? null);
    }

    public function testFailsWithoutEndpoints(): void
    {
        putenv('BLACKCAT_KMS_ENDPOINTS=');
        $cmd = new KmsListCommand(new NullLogger());

        ob_start();
        $code = $cmd->run([]);
        ob_end_clean();

        self::assertSame(1, $code);
    }
}

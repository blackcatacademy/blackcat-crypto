<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\KmsSuspendCommand;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class KmsSuspendCommandTest extends TestCase
{
    private string $envBackup = '';

    protected function setUp(): void
    {
        $this->envBackup = getenv('BLACKCAT_KMS_ENDPOINTS') ?: '';
        putenv('BLACKCAT_KMS_ENDPOINTS=a=http://localhost:7001');
    }

    protected function tearDown(): void
    {
        putenv('BLACKCAT_KMS_ENDPOINTS=' . $this->envBackup);
    }

    public function testSuspendsClient(): void
    {
        $cmd = new KmsSuspendCommand(new NullLogger());
        ob_start();
        $code = $cmd->run(['a', '5']);
        $out = ob_get_clean();

        self::assertSame(0, $code);
        self::assertStringContainsString('Suspended a for 5s', $out);
    }

    public function testFailsWithBadArgs(): void
    {
        $cmd = new KmsSuspendCommand(new NullLogger());
        ob_start();
        $code = $cmd->run([]);
        ob_end_clean();

        self::assertSame(1, $code);
    }
}

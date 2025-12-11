<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\CLI;

use BlackCat\Crypto\CLI\Command\KmsResumeCommand;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

final class KmsResumeCommandTest extends TestCase
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

    public function testResumesClient(): void
    {
        $cmd = new KmsResumeCommand(new NullLogger());
        ob_start();
        $code = $cmd->run(['a']);
        $out = ob_get_clean();

        self::assertSame(0, $code);
        self::assertStringContainsString('Resumed a', $out);
    }

    public function testFailsWithBadArgs(): void
    {
        $cmd = new KmsResumeCommand(new NullLogger());
        ob_start();
        $code = $cmd->run([]);
        ob_end_clean();

        self::assertSame(1, $code);
    }
}

<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Telemetry;

use BlackCat\Crypto\Governance\GovernanceReporter;
use BlackCat\Crypto\Telemetry\IntentCollector;
use PHPUnit\Framework\TestCase;

final class GovernanceReporterTest extends TestCase
{
    protected function setUp(): void
    {
        IntentCollector::global(new IntentCollector(recentLimit: 10));
    }

    protected function tearDown(): void
    {
        IntentCollector::global(null);
    }

    public function testApprovedAndDeniedAreRecorded(): void
    {
        $reporter = new GovernanceReporter();
        $reporter->approved([
            'tenant' => 'acme',
            'algorithm' => 'aes-256-gcm',
            'policy' => 'low-risk',
            'approval_id' => 'appr-1',
        ]);
        $reporter->denied([
            'tenant' => 'acme',
            'reason' => 'risk-high',
        ]);

        $snapshot = IntentCollector::global()?->snapshot();
        self::assertNotNull($snapshot);
        self::assertSame(2, $snapshot['counts']['governance.unwrap'] ?? 0);
        self::assertSame(1, $snapshot['tag_counts']['decision']['approved'] ?? 0);
        self::assertSame(1, $snapshot['tag_counts']['decision']['denied'] ?? 0);
        self::assertSame(1, $snapshot['tag_counts']['tenant']['acme'] ?? 0);
    }
}

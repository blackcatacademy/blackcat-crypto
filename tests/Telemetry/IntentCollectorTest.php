<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Telemetry;

use BlackCat\Crypto\Telemetry\IntentCollector;
use PHPUnit\Framework\TestCase;

final class IntentCollectorTest extends TestCase
{
    public function testCollectsCountsAndRecent(): void
    {
        $collector = new IntentCollector(recentLimit: 2);
        $collector->record('encrypt', ['ctx' => 'a']);
        $collector->record('decrypt', ['ctx' => 'b']);
        $collector->record('encrypt', ['ctx' => 'c']);

        $snapshot = $collector->snapshot();

        self::assertSame(['encrypt' => 2, 'decrypt' => 1], $snapshot['counts']);
        self::assertCount(2, $snapshot['recent']);
        self::assertSame('decrypt', $snapshot['recent'][0]['intent']);
        self::assertSame('encrypt', $snapshot['recent'][1]['intent']);
    }
}

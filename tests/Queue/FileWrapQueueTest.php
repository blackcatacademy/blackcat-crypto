<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Queue;

use BlackCat\Crypto\Queue\FileWrapQueue;
use BlackCat\Crypto\Queue\WrapJob;
use PHPUnit\Framework\TestCase;

final class FileWrapQueueTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        parent::setUp();
        $this->path = sys_get_temp_dir() . '/wrap-queue-' . uniqid('', true) . '.log';
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        @unlink($this->path);
    }

    public function testPersistsAndPeeksJobs(): void
    {
        $queue = new FileWrapQueue($this->path);
        $queue->enqueue(new WrapJob('users.pii', '{"secret":true}'));
        $queue->enqueue(new WrapJob('orders.card', '{"secret":false}'));

        self::assertSame(2, $queue->size());
        $peek = $queue->peek();
        self::assertCount(2, $peek);
        self::assertSame('users.pii', $peek[0]->context);

        $first = $queue->dequeue();
        self::assertInstanceOf(WrapJob::class, $first);
        self::assertSame('users.pii', $first->context);
        self::assertSame(1, $queue->size());
    }
}

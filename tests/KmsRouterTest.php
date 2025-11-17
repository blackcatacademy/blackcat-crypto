<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests;

use BlackCat\Crypto\Kms\KmsRouter;
use BlackCat\Crypto\Support\Payload;
use BlackCat\Crypto\Tests\Support\LoopbackKmsClient;
use PHPUnit\Framework\TestCase;

final class KmsRouterTest extends TestCase
{
    public function testContextRoutingPrefersMatchingClient(): void
    {
        $router = new KmsRouter([
            ['class' => LoopbackKmsClient::class, 'id' => 'users', 'contexts' => ['users.*']],
            ['class' => LoopbackKmsClient::class, 'id' => 'orders', 'contexts' => ['orders.*']],
        ]);

        $payload = new Payload('cipher', 'nonce', 'k1');
        $metaUsers = $router->wrap('users.pii', $payload, []);
        self::assertSame('users', $metaUsers['client']);

        $metaOrders = $router->wrap('orders.payments', $payload, []);
        self::assertSame('orders', $metaOrders['client']);
    }
}

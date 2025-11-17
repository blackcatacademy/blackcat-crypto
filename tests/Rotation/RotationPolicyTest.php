<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Rotation;

use BlackCat\Crypto\Rotation\RotationPolicyRegistry;
use BlackCat\Crypto\Support\Envelope;
use BlackCat\Crypto\Support\Payload;
use PHPUnit\Framework\TestCase;

final class RotationPolicyTest extends TestCase
{
    public function testShouldRotateWhenAgeExceeded(): void
    {
        $registry = RotationPolicyRegistry::fromArray([
            'users.*' => ['maxAgeSeconds' => 0],
        ]);
        $payload = new Payload('cipher', 'nonce', 'key');
        $envelope = new Envelope($payload, [], 'users.pii', ['createdAt' => time() - 10]);
        self::assertTrue($registry?->shouldRotate($envelope));
    }
}

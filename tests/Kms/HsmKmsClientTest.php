<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Kms;

use BlackCat\Crypto\Kms\HsmKmsClient;
use BlackCat\Crypto\Support\Payload;
use PHPUnit\Framework\TestCase;

final class HsmKmsClientTest extends TestCase
{
    public function testWrapAndUnwrapRoundTrip(): void
    {
        $secret = base64_encode(str_repeat('k', 32));
        $client = new HsmKmsClient(['id' => 'local-hsm', 'secret' => $secret]);

        $payload = new Payload(ciphertext: 'plaintext', nonce: 'abc123', keyId: 'src-key');
        $metadata = $client->wrap('user.email', $payload);

        self::assertArrayHasKey('ciphertext', $metadata);
        self::assertSame('local-hsm', $metadata['keyId']);

        $unwrapped = $client->unwrap('user.email', $metadata);

        self::assertSame('plaintext', $unwrapped->ciphertext);
        self::assertSame('abc123', $unwrapped->nonce);
        self::assertSame('local-hsm', $unwrapped->keyId);
    }

    public function testHealthReturnsOk(): void
    {
        $secret = base64_encode(str_repeat('x', 32));
        $client = new HsmKmsClient(['secret' => $secret]);
        $health = $client->health();

        self::assertSame('ok', $health['status']);
        self::assertArrayHasKey('client', $health);
    }

    public function testGuardDisablesWrap(): void
    {
        $secret = base64_encode(str_repeat('y', 32));
        $client = new HsmKmsClient([
            'secret' => $secret,
            'allow_wrap' => false,
        ]);

        $this->expectException(\RuntimeException::class);
        $client->wrap('pii', new Payload(ciphertext: 'noop', nonce: 'n1'));
    }

    public function testSuspendFileBlocksUnwrap(): void
    {
        $secret = base64_encode(str_repeat('z', 32));
        $suspend = tempnam(sys_get_temp_dir(), 'hsm-suspend-') ?: '';
        file_put_contents($suspend, json_encode(['suspend' => false]));

        $client = new HsmKmsClient([
            'secret' => $secret,
            'suspend_path' => $suspend,
        ]);

        $metadata = $client->wrap('pii', new Payload(ciphertext: 'text', nonce: 'n2'));

        file_put_contents($suspend, json_encode([
            'suspend' => true,
            'reason' => 'maintenance',
            'until_ms' => (int)(microtime(true) * 1000) + 60_000,
        ]));

        try {
            $this->expectException(\RuntimeException::class);
            $client->unwrap('pii', $metadata);
        } finally {
            @unlink($suspend);
        }
    }

    public function testHealthReportsSuspendAndLatency(): void
    {
        $secret = base64_encode(str_repeat('q', 32));
        $suspend = tempnam(sys_get_temp_dir(), 'hsm-suspend-') ?: '';
        file_put_contents($suspend, json_encode(['suspend' => true, 'reason' => 'ops']));

        $client = new HsmKmsClient([
            'secret' => $secret,
            'suspend_path' => $suspend,
            'latency_ms' => 25,
        ]);

        $health = $client->health();

        self::assertSame(25, $health['latency_ms']);
        self::assertTrue($health['suspend']['suspend']);
        self::assertSame('ops', $health['suspend']['reason'] ?? null);

        @unlink($suspend);
    }
}

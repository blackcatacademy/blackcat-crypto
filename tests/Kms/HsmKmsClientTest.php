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
}

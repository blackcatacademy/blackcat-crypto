<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Queue;

use BlackCat\Crypto\AEAD\XChaCha20Cipher;
use BlackCat\Crypto\CryptoManager;
use BlackCat\Crypto\Hmac\HmacService;
use BlackCat\Crypto\Keyring\InMemoryKeyResolver;
use BlackCat\Crypto\Keyring\KeyMaterial;
use BlackCat\Crypto\Keyring\KeyRegistry;
use BlackCat\Crypto\Keyring\KeySlot;
use BlackCat\Crypto\Kms\KmsRouter;
use BlackCat\Crypto\Queue\InMemoryWrapQueue;
use BlackCat\Crypto\Queue\RotationCoordinator;
use BlackCat\Crypto\Rotation\RotationPolicyRegistry;
use BlackCat\Crypto\Tests\Support\LoopbackKmsClient;
use PHPUnit\Framework\TestCase;

final class RotationCoordinatorTest extends TestCase
{
    public function testAutoSchedulesAndProcessesRotation(): void
    {
        $slot = KeySlot::default('users.pii');
        $resolver = new InMemoryKeyResolver([
            $slot->name() => [new KeyMaterial('k1', random_bytes(32), $slot->name())],
        ]);
        $registry = new KeyRegistry($resolver);
        $kms = new KmsRouter([
            ['class' => LoopbackKmsClient::class, 'id' => 'loop'],
        ]);
        $rotation = RotationPolicyRegistry::fromArray([
            'users.*' => ['maxWraps' => 1],
        ]);
        $queue = new InMemoryWrapQueue();
        $crypto = CryptoManager::fromComponents(
            $registry,
            new XChaCha20Cipher(),
            new HmacService($registry),
            $kms,
            $rotation,
            $queue
        );

        $envelope = $crypto->encryptContext('users.pii', 'secret');
        $this->assertNotNull($queue->dequeue(), 'Rotation job should be scheduled.');

        $queue->enqueue(new \BlackCat\Crypto\Queue\WrapJob('users.pii', $envelope->encode()));
        $rotationCoordinator = new RotationCoordinator($crypto, $queue);
        $processed = $rotationCoordinator->process();
        self::assertSame(1, $processed);
    }
}

<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests;

use BlackCat\Crypto\AEAD\XChaCha20Cipher;
use BlackCat\Crypto\CryptoManager;
use BlackCat\Crypto\Hmac\HmacService;
use BlackCat\Crypto\Keyring\InMemoryKeyResolver;
use BlackCat\Crypto\Keyring\KeyMaterial;
use BlackCat\Crypto\Keyring\KeyRegistry;
use BlackCat\Crypto\Keyring\KeySlot;
use BlackCat\Crypto\Kms\KmsRouter;
use BlackCat\Crypto\Config\CryptoConfig;
use BlackCat\Crypto\Tests\Support\LoopbackKmsClient;
use PHPUnit\Framework\TestCase;

final class CryptoManagerTest extends TestCase
{
    public function testEncryptAndDecryptContext(): void
    {
        $keyBytes = random_bytes(32);
        $slot = KeySlot::default('users.pii');
        $resolver = new InMemoryKeyResolver([
            $slot->name() => [new KeyMaterial('k1', $keyBytes, $slot->name())],
        ]);
        $registry = new KeyRegistry($resolver);

        $manager = CryptoManager::fromComponents(
            $registry,
            new XChaCha20Cipher(),
            new HmacService($registry),
            new KmsRouter([
                ['class' => LoopbackKmsClient::class, 'id' => 'loop'],
            ])
        );

        $envelope = $manager->encryptContext('users.pii', 'secret-data');
        $serialized = $envelope->encode();
        $plain = $manager->decryptContext('users.pii', $serialized);
        self::assertSame('secret-data', $plain);
    }
}

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

    public function testDecryptContextFallsBackWhenKeyIdHintIsWrong(): void
    {
        $slot = KeySlot::default('users.pii');

        $k1 = new KeyMaterial('k1', random_bytes(32), $slot->name());
        $registryV1 = new KeyRegistry(new InMemoryKeyResolver([
            $slot->name() => [$k1],
        ]));

        $managerV1 = CryptoManager::fromComponents(
            $registryV1,
            new XChaCha20Cipher(),
            new HmacService($registryV1),
            new KmsRouter([])
        );

        $serialized = $managerV1->encryptContext($slot->name(), 'secret-data')->encode();

        $k2 = new KeyMaterial('k2', random_bytes(32), $slot->name());
        $registryRotated = new KeyRegistry(new InMemoryKeyResolver([
            // oldest -> newest
            $slot->name() => [$k1, $k2],
        ]));

        $managerRotated = CryptoManager::fromComponents(
            $registryRotated,
            new XChaCha20Cipher(),
            new HmacService($registryRotated),
            new KmsRouter([])
        );

        $decoded = json_decode($serialized, true);
        self::assertIsArray($decoded);
        self::assertIsArray($decoded['local'] ?? null);
        $decoded['local']['keyId'] = 'k2'; // wrong hint; ciphertext was produced with k1
        $tampered = json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        self::assertIsString($tampered);

        $plain = $managerRotated->decryptContext($slot->name(), $tampered);
        self::assertSame('secret-data', $plain);

        $registryWrongOnly = new KeyRegistry(new InMemoryKeyResolver([
            $slot->name() => [$k2],
        ]));
        $managerWrongOnly = CryptoManager::fromComponents(
            $registryWrongOnly,
            new XChaCha20Cipher(),
            new HmacService($registryWrongOnly),
            new KmsRouter([])
        );

        $this->expectException(\Throwable::class);
        $managerWrongOnly->decryptContext($slot->name(), $serialized);
    }

    public function testHmacWithKeyIdExposesSigningKey(): void
    {
        $slot = KeySlot::default('core.hmac.email');
        $resolver = new InMemoryKeyResolver([
            $slot->name() => [new KeyMaterial('k1', random_bytes(32), $slot->name())],
        ]);
        $registry = new KeyRegistry($resolver);

        $manager = CryptoManager::fromComponents(
            $registry,
            new XChaCha20Cipher(),
            new HmacService($registry),
            new KmsRouter([])
        );

        $out = $manager->hmacWithKeyId('core.hmac.email', 'hello');
        self::assertSame('k1', $out['keyId']);
        self::assertSame(32, strlen($out['signature']));
        self::assertSame($out['signature'], $manager->hmac('core.hmac.email', 'hello'));
    }

    public function testHmacVerifyIsRotationSafeAndSupportsCandidates(): void
    {
        $slot = KeySlot::default('core.hmac.email');
        $resolver = new InMemoryKeyResolver([
            // Ordered oldest -> newest; resolver returns end() as latest.
            $slot->name() => [
                new KeyMaterial('k1', random_bytes(32), $slot->name()),
                new KeyMaterial('k2', random_bytes(32), $slot->name()),
            ],
        ]);
        $registry = new KeyRegistry($resolver);
        $hmac = new HmacService($registry);

        $manager = CryptoManager::fromComponents(
            $registry,
            new XChaCha20Cipher(),
            $hmac,
            new KmsRouter([])
        );

        $msg = 'rotate-me';

        $sigOld = $hmac->signWithKeyId($slot->name(), $msg);
        self::assertSame('k2', $sigOld['keyId']); // newest key
        self::assertTrue($manager->verifyHmac($slot->name(), $msg, $sigOld['signature']));
        self::assertTrue($manager->verifyHmacWithKeyId($slot->name(), $msg, $sigOld['signature'], $sigOld['keyId']));

        // Manually sign with the old key id.
        $oldKey = $manager->keyMaterial($slot->name(), 'k1');
        $sigOldVer = hash_hmac('sha256', $msg, $oldKey->bytes, true);
        self::assertTrue($manager->verifyHmac($slot->name(), $msg, $sigOldVer));
        self::assertTrue($manager->verifyHmacWithKeyId($slot->name(), $msg, $sigOldVer, 'k1'));
        self::assertTrue($manager->verifyHmacWithKeyId($slot->name(), $msg, $sigOldVer, 'k2'));

        $candidates = $manager->hmacCandidates($slot->name(), $msg);
        self::assertCount(2, $candidates);
        self::assertSame(['k2', 'k1'], array_map(static fn(array $c) => $c['keyId'], $candidates));
    }
}

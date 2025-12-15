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

        $candidates = $manager->hmacCandidates($slot->name(), $msg);
        self::assertCount(2, $candidates);
        self::assertSame(['k2', 'k1'], array_map(static fn(array $c) => $c['keyId'], $candidates));
    }
}

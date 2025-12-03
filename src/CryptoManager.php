<?php
declare(strict_types=1);

namespace BlackCat\Crypto;

use BlackCat\Crypto\Config\CryptoConfig;
use BlackCat\Crypto\AEAD\AeadCipherInterface;
use BlackCat\Crypto\AEAD\XChaCha20Cipher;
use BlackCat\Crypto\Hmac\HmacService;
use BlackCat\Crypto\Keyring\KeyRegistry;
use BlackCat\Crypto\Kms\KmsRouter;
use BlackCat\Crypto\Support\Envelope;
use BlackCat\Crypto\Support\Payload;
use BlackCat\Crypto\Rotation\RotationPolicyRegistry;
use BlackCat\Crypto\Queue\WrapQueueInterface;
use BlackCat\Crypto\Queue\WrapJob;
use Psr\Log\LoggerInterface;

/**
 * Facade pro veškerou kryptografii v BlackCat.
 * - AEAD šifrování s lokálními klíči a HMAC sloty
 * - Double-envelope (lokální AEAD + KMS wrap)
 * - Jednotný vstup pro další repozitáře
 */
final class CryptoManager
{
    private KeyRegistry $keyRegistry;
    private AeadCipherInterface $aead;
    private HmacService $hmac;
    private KmsRouter $kms;
    private ?RotationPolicyRegistry $rotationPolicies;
    private ?WrapQueueInterface $wrapQueue;
    private ?LoggerInterface $logger;

    private function __construct(
        KeyRegistry $keyRegistry,
        AeadCipherInterface $aead,
        HmacService $hmac,
        KmsRouter $kms,
        ?RotationPolicyRegistry $rotationPolicies = null,
        ?WrapQueueInterface $wrapQueue = null,
        ?LoggerInterface $logger = null,
    ) {
        $this->keyRegistry = $keyRegistry;
        $this->aead = $aead;
        $this->hmac = $hmac;
        $this->kms = $kms;
        $this->rotationPolicies = $rotationPolicies;
        $this->wrapQueue = $wrapQueue;
        $this->logger = $logger;
    }

    public static function boot(CryptoConfig $config, ?LoggerInterface $logger = null): self
    {
        $registry = KeyRegistry::fromConfig($config, $logger);
        $aead = $config->aeadFactory()
            ? ($config->aeadFactory())($registry, $logger)
            : self::buildAead($config->aeadDriver(), $registry, $logger);
        $hmac = new HmacService($registry, $logger);
        $kms = new KmsRouter($config->kmsConfig(), $logger);
        $rotation = RotationPolicyRegistry::fromArray($config->rotationPolicies());
        $queueFactory = $config->wrapQueueFactory();
        $queue = $queueFactory ? $queueFactory() : null;
        return new self($registry, $aead, $hmac, $kms, $rotation, $queue, $logger);
    }

    public static function fromComponents(
        KeyRegistry $registry,
        AeadCipherInterface $aead,
        HmacService $hmac,
        KmsRouter $kms,
        ?RotationPolicyRegistry $rotation = null,
        ?WrapQueueInterface $wrapQueue = null,
        ?LoggerInterface $logger = null
    ): self {
        return new self($registry, $aead, $hmac, $kms, $rotation, $wrapQueue, $logger);
    }

    public function withWrapQueue(WrapQueueInterface $queue): self
    {
        $clone = clone $this;
        $clone->wrapQueue = $queue;
        return $clone;
    }

    /**
     * Encrypt plaintext for a logical context (např. `users.pii`).
     * Vrátí `Envelope`, které obsahuje metadata (KMS host, lokální slot, verze…).
     */
    public function encryptContext(string $context, string $plaintext, array $options = []): Envelope
    {
        $localKey = $this->keyRegistry->deriveAeadKey($context);
        $payload = $this->aead->encrypt($plaintext, $context, $localKey);
        $wrapCount = ($options['wrapCount'] ?? 0) + 1;
        $wrapped = $this->kms->wrap($context, $payload, $this->keyRegistry->kmsBindings($context), ['preferredClient' => $options['preferredClient'] ?? null]);
        $wrapped['wrapCount'] = $wrapCount;
        $envelope = Envelope::fromLayers($payload, $wrapped, $context);
        $this->maybeScheduleRotation($envelope);
        return $envelope;
    }

    /**
     * Decrypt envelope – využívá metadata pro výběr správného lokálního klíče i KMS unwrap.
     */
    public function decryptContext(string $context, string $serializedEnvelope): string
    {
        $envelope = Envelope::decode($serializedEnvelope);
        $wrapped = $this->kms->unwrap($context, $envelope->kmsMetadata);
        $localKey = $this->keyRegistry->deriveAeadKey($context, $envelope->local->keyId);
        $plaintext = $this->aead->decrypt($wrapped, $context, $localKey);
        $this->maybeScheduleRotation($envelope);
        return $plaintext;
    }

    /**
     * Convenience pro jednorázové šifrování bez KMS (např. ephemeral secrets).
     */
    public function encryptLocal(string $slot, string $plaintext): Payload
    {
        $key = $this->keyRegistry->deriveAeadKey($slot);
        return $this->aead->encrypt($plaintext, $slot, $key);
    }

    public function decryptLocal(string $slot, Payload $payload): string
    {
        $key = $this->keyRegistry->deriveAeadKey($slot, $payload->keyId);
        $plaintext = $this->aead->decrypt($payload, $slot, $key);
        return $plaintext;
    }

    public function decryptLocalWithAnyKey(string $slot, string $nonce, string $ciphertext): ?string
    {
        $materials = $this->keyRegistry->all($slot);
        foreach ($materials as $material) {
            try {
                $payload = new Payload($ciphertext, $nonce, $material->id);
                return $this->decryptLocal($slot, $payload);
            } catch (\Throwable $e) {
                $this->logger?->debug('decryptLocalWithAnyKey failed candidate', [
                    'slot' => $slot,
                    'key' => $material->id,
                    'error' => $e->getMessage(),
                ]);
                continue;
            }
        }

        if ($this->logger) {
            try {
                $this->logger->warning('decryptLocalWithAnyKey exhausted all candidates', ['slot' => $slot]);
            } catch (\Throwable $_) {
            }
        }

        return null;
    }

    public function hmac(string $slot, string $message): string
    {
        return $this->hmac->sign($slot, $message);
    }

    public function verifyHmac(string $slot, string $message, string $signature): bool
    {
        return $this->hmac->verify($slot, $message, $signature);
    }

    public function keyMaterial(string $slot, ?string $forceKeyId = null): \BlackCat\Crypto\Keyring\KeyMaterial
    {
        return $this->keyRegistry->deriveAeadKey($slot, $forceKeyId);
    }

    /**
     * @return list<\BlackCat\Crypto\Keyring\KeyMaterial>
     */
    public function allKeyMaterial(string $slot): array
    {
        return $this->keyRegistry->all($slot);
    }

    private static function buildAead(string $driver, KeyRegistry $registry, ?LoggerInterface $logger): AeadCipherInterface
    {
        return match ($driver) {
            'hybrid' => new \BlackCat\Crypto\AEAD\HybridKyberAesCipher($logger),
            default => new XChaCha20Cipher($logger),
        };
    }

    private function maybeScheduleRotation(Envelope $envelope): void
    {
        if ($this->rotationPolicies === null || $this->wrapQueue === null) {
            return;
        }
        if ($this->rotationPolicies->shouldRotate($envelope)) {
            $this->wrapQueue->enqueue(new WrapJob($envelope->context, $envelope->encode()));
        }
    }
}

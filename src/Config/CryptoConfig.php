<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Config;

use BlackCat\Crypto\Queue\FileWrapQueue;
use BlackCat\Crypto\Queue\InMemoryWrapQueue;
use Closure;

final class CryptoConfig
{
    public function __construct(
        private readonly array $keySources = [],
        private readonly array $slots = [],
        private readonly array $kms = [],
        private readonly array $rotationPolicies = [],
        private readonly string $aeadDriver = 'xchacha',
        private readonly ?Closure $aeadFactory = null,
        private readonly ?Closure $wrapQueueFactory = null,
        private readonly ?string $manifestPath = null,
    ) {}

    public static function fromEnv(array $env = []): self
    {
        $env = $env ?: $_ENV + $_SERVER;
        $keysDir = $env['BLACKCAT_KEYS_DIR'] ?? $env['APP_KEYS_DIR'] ?? null;
        $kms = json_decode($env['BLACKCAT_KMS_ENDPOINTS'] ?? '[]', true) ?: [];
        $rotation = json_decode($env['BLACKCAT_CRYPTO_ROTATION'] ?? '[]', true) ?: [];
        $driver = strtolower((string)($env['BLACKCAT_CRYPTO_AEAD'] ?? 'xchacha'));
        $queueSpec = (string)($env['BLACKCAT_CRYPTO_WRAP_QUEUE'] ?? '');
        $queueFactory = null;
        if ($queueSpec !== '') {
            $queueFactory = static function () use ($queueSpec) {
                if ($queueSpec === 'memory') {
                    return new InMemoryWrapQueue();
                }
                $path = str_starts_with($queueSpec, 'file://')
                    ? substr($queueSpec, 7)
                    : $queueSpec;
                return new FileWrapQueue($path);
            };
        }
        $manifestPath = $env['BLACKCAT_CRYPTO_MANIFEST'] ?? null;
        $manifestSlots = [];
        $manifestRotation = [];
        if ($manifestPath && is_file($manifestPath)) {
            [$manifestSlots, $manifestRotation] = self::loadManifest($manifestPath);
        }

        if (!empty($manifestRotation)) {
            $rotation = array_replace($manifestRotation, $rotation);
        }

        return new self(
            keySources: [
                ['type' => 'filesystem', 'path' => $keysDir],
                ['type' => 'env', 'prefix' => 'BC_KEY_'],
            ],
            slots: $manifestSlots,
            kms: $kms,
            rotationPolicies: $rotation,
            aeadDriver: in_array($driver, ['xchacha','hybrid'], true) ? $driver : 'xchacha',
            wrapQueueFactory: $queueFactory,
            manifestPath: $manifestPath && is_file($manifestPath) ? $manifestPath : null,
        );
    }

    /** @return array<int,array<string,mixed>> */
    public function keySources(): array
    {
        return $this->keySources;
    }

    /** @return array<string,array<string,mixed>> */
    public function slots(): array
    {
        return $this->slots;
    }

    /** @return array<string,mixed> */
    public function kmsConfig(): array
    {
        return $this->kms;
    }

    /** @return array<string,array<string,mixed>> */
    public function rotationPolicies(): array
    {
        return $this->rotationPolicies;
    }

    /** @return Closure|null */
    public function aeadFactory(): ?Closure
    {
        return $this->aeadFactory;
    }

    public function aeadDriver(): string
    {
        return $this->aeadFactory ? 'custom' : $this->aeadDriver;
    }

    /** @return Closure|null */
    public function wrapQueueFactory(): ?Closure
    {
        return $this->wrapQueueFactory;
    }

    public function manifestPath(): ?string
    {
        return $this->manifestPath;
    }

    /**
     * @return array{0:array<string,mixed>,1:array<string,mixed>}
     */
    private static function loadManifest(string $path): array
    {
        $json = file_get_contents($path);
        if ($json === false) {
            throw new \RuntimeException('Cannot read manifest ' . $path);
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new \RuntimeException('Manifest ' . $path . ' is not valid JSON');
        }

        $slots = $data['slots'] ?? [];
        $rotation = $data['rotation'] ?? [];
        if (!is_array($slots)) {
            $slots = [];
        }
        if (!is_array($rotation)) {
            $rotation = [];
        }
        return [$slots, $rotation];
    }
}

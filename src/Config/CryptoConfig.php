<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Config;

use BlackCat\Crypto\Queue\FileWrapQueue;
use BlackCat\Crypto\Queue\InMemoryWrapQueue;
use Closure;

final class CryptoConfig
{
    /**
     * @param list<array<string,mixed>> $keySources
     * @param array<string,array<string,mixed>> $slots
     * @param array<int|string,mixed> $kms
     * @param array<string,array<string,mixed>> $rotationPolicies
     */
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

    /** @param array<string,mixed> $env */
    public static function fromEnv(array $env = []): self
    {
        // merge all possible env sources so putenv/$_ENV/$_SERVER are seen in tests and runtime
        $env = $env ?: array_merge((array)getenv(), $_ENV, $_SERVER);
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

        // Fallback: parse comma-separated KMS endpoints like "a=http://host:7001,b=hsm://slot1".
        if ($kms === [] && isset($env['BLACKCAT_KMS_ENDPOINTS']) && $env['BLACKCAT_KMS_ENDPOINTS'] !== '') {
            $pairs = array_filter(array_map('trim', explode(',', (string)$env['BLACKCAT_KMS_ENDPOINTS'])));
            foreach ($pairs as $pair) {
                if (!str_contains($pair, '=')) {
                    continue;
                }
                [$id, $endpoint] = array_map('trim', explode('=', $pair, 2));
                if ($id === '' || $endpoint === '') {
                    continue;
                }
                $scheme = parse_url($endpoint, PHP_URL_SCHEME) ?: '';
                $type = $scheme === 'hsm' ? 'hsm' : 'http';
                $kms[] = [
                    'id' => $id,
                    'endpoint' => $endpoint,
                    'type' => $type,
                ];
            }
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

    /** @return list<array<string,mixed>> */
    public function keySources(): array
    {
        return $this->keySources;
    }

    /** @return array<string,array<string,mixed>> */
    public function slots(): array
    {
        return $this->slots;
    }

    /** @return array<int|string,mixed> */
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

<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Keyring;

use BlackCat\Crypto\Contracts\KeyResolverInterface;
use BlackCat\Crypto\Support\Random;
use Psr\Log\LoggerInterface;

final class MultiSourceKeyResolver implements KeyResolverInterface
{
    public function __construct(
        private readonly array $sources,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function resolve(KeySlot $slot, ?string $forceKeyId = null): KeyMaterial
    {
        $candidates = $this->loadAllKeys($slot);
        if ($forceKeyId !== null) {
            foreach ($candidates as $candidate) {
                if ($candidate->id === $forceKeyId) {
                    return $candidate;
                }
            }
        }
        return end($candidates) ?: throw new \RuntimeException("No key material for slot {$slot->name()}");
    }

    public function kmsBindings(KeySlot $slot): array
    {
        $bindings = [];
        foreach ($this->sources as $source) {
            if (($source['type'] ?? '') !== 'kms') {
                continue;
            }
            $bindings[] = new KeyMaterial(
                id: $source['id'] ?? Random::hex(8),
                bytes: $source['token'] ?? '',
                slot: $slot->name(),
                metadata: $source,
            );
        }
        return $bindings;
    }

    public function all(KeySlot $slot): array
    {
        return $this->loadAllKeys($slot);
    }

    /** @return list<KeyMaterial> */
    private function loadAllKeys(KeySlot $slot): array
    {
        $keys = [];
        foreach ($this->sources as $source) {
            $type = $source['type'] ?? 'filesystem';
            $loader = $type . 'Loader';
            if (!method_exists($this, $loader)) {
                continue;
            }
            $keys = array_merge($keys, $this->{$loader}($slot, $source));
        }
        if ($keys === []) {
            throw new \RuntimeException('No key sources yielded data');
        }
        return $keys;
    }

    /** @return list<KeyMaterial> */
    private function filesystemLoader(KeySlot $slot, array $source): array
    {
        $dir = $source['path'] ?? null;
        if (!$dir || !is_dir($dir)) {
            return [];
        }
        $keyName = strtolower($slot->keyName());
        $variants = array_values(array_unique([
            $keyName,
            str_replace(['.', '-'], '_', $keyName),
            str_replace(['.', '-', '_'], '', $keyName),
        ]));

        $allFiles = glob($dir . '/*.key') ?: [];
        sort($allFiles, SORT_STRING);

        $matched = [];
        foreach ($allFiles as $file) {
            $base = strtolower(basename($file));
            foreach ($variants as $variant) {
                if ($variant !== '' && str_contains($base, $variant)) {
                    $matched[] = $file;
                    continue 2;
                }
            }
        }

        // Fallback: if nothing matched, take everything (deterministic order).
        $targets = $matched === [] ? $allFiles : $matched;

        $result = [];
        foreach ($targets as $file) {
            $bytes = @file_get_contents($file);
            if ($bytes === false) {
                continue;
            }
            $result[] = new KeyMaterial(
                id: basename($file),
                bytes: $bytes,
                slot: $slot->name(),
                metadata: ['source' => 'filesystem', 'path' => $file],
            );
        }
        return $result;
    }

    /** @return list<KeyMaterial> */
    private function envLoader(KeySlot $slot, array $source): array
    {
        $prefix = $source['prefix'] ?? 'BC_KEY_';
        $keys = [];
        foreach ($_ENV + $_SERVER as $name => $value) {
            if (!str_starts_with($name, $prefix . strtoupper($slot->keyName()))) {
                continue;
            }
            $keys[] = new KeyMaterial($name, (string)$value, $slot->name(), ['source' => 'env']);
        }
        return $keys;
    }
}

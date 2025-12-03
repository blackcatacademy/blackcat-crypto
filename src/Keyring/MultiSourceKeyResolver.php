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
        $files = glob($dir . '/' . strtolower($slot->keyName()) . '*.key') ?: [];
        sort($files);
        $result = [];
        foreach ($files as $file) {
            $bytes = file_get_contents($file);
            if ($bytes === false) {
                continue;
            }
            $result[] = new KeyMaterial(basename($file), $bytes, $slot->name(), ['source' => 'filesystem']);
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

<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Kms;

use BlackCat\Crypto\Contracts\KmsClientInterface;
use BlackCat\Crypto\Support\Payload;
use BlackCat\Crypto\Kms\HttpKmsClient;
use BlackCat\Crypto\Kms\HsmKmsClient;
use Psr\Log\LoggerInterface;

final class KmsRouter
{
    /** @var list<array{client:KmsClientInterface,weight:int,contexts:list<string>}> */
    private array $clients = [];
    /** @var array<string,int> */
    private array $suspendedUntil = [];
    private string $suspendedCachePath;

    public function __construct(array $config, private readonly ?LoggerInterface $logger = null)
    {
        $this->suspendedCachePath = (string)($config['suspended_cache'] ?? getenv('BLACKCAT_KMS_SUSPEND_CACHE') ?: sys_get_temp_dir() . '/blackcat-kms-suspend.json');
        $this->loadSuspensions();

        foreach ($config as $definition) {
            // Ignore non-client config nodes (e.g., cache/suspend metadata).
            if (!is_array($definition)) {
                continue;
            }
            if (!isset($definition['type']) && !isset($definition['class'])) {
                continue;
            }

            $client = $this->clientFromDefinition($definition);
            $this->clients[] = [
                'client' => $client,
                'weight' => max(1, (int)($definition['weight'] ?? 1)),
                'contexts' => array_values((array)($definition['contexts'] ?? [])),
            ];
        }
    }

    public function wrap(string $context, Payload $payload, array $bindings, array $options = []): array
    {
        $client = $this->pickClient($context, $options['preferredClient'] ?? null);
        if ($client === null) {
            return $this->localMetadata($payload);
        }

        $meta = $client->wrap($context, $payload);
        $meta['client'] = $client->id();
        return $meta;
    }

    public function unwrap(string $context, array $metadata): Payload
    {
        $clientId = $metadata['client'] ?? null;
        if ($clientId === null || $clientId === 'local') {
            $cipher = (string)($metadata['ciphertext'] ?? '');
            $nonce = (string)($metadata['nonce'] ?? '');
            $cipherDecoded = base64_decode($cipher, true);
            $nonceDecoded = base64_decode($nonce, true);
            if ($cipherDecoded === false || $nonceDecoded === false) {
                throw new \RuntimeException('Invalid local metadata encoding');
            }
            return new Payload(
                $cipherDecoded,
                $nonceDecoded,
                (string)($metadata['keyId'] ?? '')
            );
        }
        foreach ($this->clients as $entry) {
            $client = $entry['client'];
            if ($client->id() === $clientId) {
                return $client->unwrap($context, $metadata);
            }
        }
        throw new \RuntimeException('Unknown KMS client ' . $clientId);
    }

    public function health(): array
    {
        $health = [];
        foreach ($this->clients as $entry) {
            $health[] = [
                'client' => $entry['client']->id(),
                'status' => $entry['client']->health(),
                'suspended' => isset($this->suspendedUntil[$entry['client']->id()]) && $this->suspendedUntil[$entry['client']->id()] > time(),
            ];
        }
        return $health;
    }

    public function suspend(string $clientId, int $ttlSeconds): void
    {
        $until = time() + max(1, $ttlSeconds);
        $this->suspendedUntil[$clientId] = $until;
        $this->persistSuspensions();
        $this->logger?->warning('crypto.kms.suspend', ['client' => $clientId, 'until' => $until]);
    }

    public function release(string $clientId): void
    {
        if (isset($this->suspendedUntil[$clientId])) {
            unset($this->suspendedUntil[$clientId]);
            $this->persistSuspensions();
            $this->logger?->info('crypto.kms.resume', ['client' => $clientId]);
        }
    }

    /**
     * @return list<array{id:string,type:string,weight:int,contexts:list<string>,suspendedUntil:int|null}>
     */
    public function describe(): array
    {
        $out = [];
        foreach ($this->clients as $entry) {
            $client = $entry['client'];
            $id = $client->id();
            $out[] = [
                'id' => $id,
                'type' => $client instanceof HsmKmsClient ? 'hsm' : 'http',
                'weight' => $entry['weight'],
                'contexts' => $entry['contexts'],
                'suspendedUntil' => $this->suspendedUntil[$id] ?? null,
            ];
        }
        return $out;
    }

    private function pickClient(string $context, ?string $preferred): ?KmsClientInterface
    {
        if ($preferred !== null) {
            foreach ($this->clients as $entry) {
                if ($entry['client']->id() === $preferred) {
                    return $entry['client'];
                }
            }
        }
        $candidates = $this->filterByContext($context);
        if ($candidates === []) {
            return null;
        }
        $total = array_sum(array_map(fn($entry) => $entry['weight'], $candidates));
        $rand = random_int(1, $total);
        $running = 0;
        foreach ($candidates as $entry) {
            $running += $entry['weight'];
            if ($rand <= $running) {
                return $entry['client'];
            }
        }
        return $candidates[array_key_last($candidates)]['client'];
    }

    /** @return list<array{client:KmsClientInterface,weight:int,contexts:list<string>}> */
    private function filterByContext(string $context): array
    {
        $matches = [];
        foreach ($this->clients as $entry) {
            $clientId = $entry['client']->id();
            if (isset($this->suspendedUntil[$clientId]) && $this->suspendedUntil[$clientId] > time()) {
                continue;
            }
            $contexts = $entry['contexts'];
            if ($contexts === [] || $this->matchesAny($context, $contexts)) {
                $matches[] = $entry;
            }
        }
        return $matches;
    }

    private function matchesAny(string $context, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            $pattern = str_replace(['.', '*'], ['\.', '.*'], $pattern);
            if (preg_match('~^' . $pattern . '$~i', $context)) {
                return true;
            }
        }
        return false;
    }

    private function clientFromDefinition(array $definition): KmsClientInterface
    {
        $type = $definition['type'] ?? 'http';
        $class = $definition['class'] ?? null;
        if ($class && class_exists($class)) {
            return new $class($definition);
        }
        if ($type === 'hsm') {
            return new HsmKmsClient($definition);
        }
        return new HttpKmsClient($definition);
    }

    private function localMetadata(Payload $payload): array
    {
        return [
            'client' => 'local',
            // Store as base64 to keep envelope JSON-serializable.
            'ciphertext' => base64_encode($payload->ciphertext),
            'nonce' => base64_encode($payload->nonce),
            'keyId' => $payload->keyId,
            'wrapCount' => $payload->meta['wrapCount'] ?? 0,
        ];
    }

    private function loadSuspensions(): void
    {
        if (!is_file($this->suspendedCachePath)) {
            return;
        }
        $json = file_get_contents($this->suspendedCachePath);
        if ($json === false) {
            return;
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return;
        }
        $now = time();
        foreach ($data as $clientId => $until) {
            if (!is_int($until)) {
                continue;
            }
            if ($until > $now) {
                $this->suspendedUntil[$clientId] = $until;
            }
        }
    }

    private function persistSuspensions(): void
    {
        $dir = dirname($this->suspendedCachePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        file_put_contents($this->suspendedCachePath, json_encode($this->suspendedUntil));
    }
}

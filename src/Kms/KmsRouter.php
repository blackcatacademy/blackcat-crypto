<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Kms;

use BlackCat\Crypto\Contracts\KmsClientInterface;
use BlackCat\Crypto\Support\Payload;
use Psr\Log\LoggerInterface;

final class KmsRouter
{
    /** @var list<array{client:KmsClientInterface,weight:int,contexts:list<string>}> */
    private array $clients = [];
    /** @var array<string,int> */
    private array $suspendedUntil = [];

    public function __construct(array $config, private readonly ?LoggerInterface $logger = null)
    {
        foreach ($config as $definition) {
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
        $meta = $client->wrap($context, $payload);
        $meta['client'] = $client->id();
        return $meta;
    }

    public function unwrap(string $context, array $metadata): Payload
    {
        $clientId = $metadata['client'] ?? null;
        foreach ($this->clients as $client) {
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
        $this->logger?->warning('crypto.kms.suspend', ['client' => $clientId, 'until' => $until]);
    }

    public function release(string $clientId): void
    {
        if (isset($this->suspendedUntil[$clientId])) {
            unset($this->suspendedUntil[$clientId]);
            $this->logger?->info('crypto.kms.resume', ['client' => $clientId]);
        }
    }

    private function pickClient(string $context, ?string $preferred): KmsClientInterface
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
            throw new \RuntimeException('No KMS clients configured');
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
        return new HttpKmsClient($definition);
    }
}

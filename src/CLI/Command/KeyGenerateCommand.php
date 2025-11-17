<?php
declare(strict_types=1);

namespace BlackCat\Crypto\CLI\Command;

use Psr\Log\LoggerInterface;

final class KeyGenerateCommand implements CommandInterface
{
    public function __construct(private readonly LoggerInterface $logger) {}

    public function name(): string { return 'key:generate'; }
    public function description(): string { return 'Generate a random key for a given slot.'; }

    public function run(array $args): int
    {
        $slot = $args[0] ?? null;
        $output = $args[1] ?? null;
        if (!$slot || !$output) {
            fwrite(STDERR, "Usage: key:generate <slot> <output-file>\n");
            return 1;
        }
        $bytes = random_bytes(32);
        if (file_put_contents($output, $bytes) === false) {
            $this->logger->error('key-generate-failed', ['slot' => $slot, 'output' => $output]);
            fwrite(STDERR, "Failed to write key file\n");
            return 1;
        }
        chmod($output, 0600);
        $this->logger->info('key-generated', ['slot' => $slot, 'output' => $output]);
        echo sprintf("Generated key for %s at %s\n", $slot, $output);
        return 0;
    }
}

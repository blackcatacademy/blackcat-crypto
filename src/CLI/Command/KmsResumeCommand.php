<?php
declare(strict_types=1);

namespace BlackCat\Crypto\CLI\Command;

use BlackCat\Crypto\Config\CryptoConfig;
use BlackCat\Crypto\Kms\KmsRouter;
use Psr\Log\LoggerInterface;

final class KmsResumeCommand implements CommandInterface
{
    public function __construct(private readonly LoggerInterface $logger) {}

    public function name(): string
    {
        return 'kms:resume';
    }

    public function description(): string
    {
        return 'Resume a suspended KMS client immediately.';
    }

    /** @param list<string> $args */
    public function run(array $args): int
    {
        $clientId = $args[0] ?? null;
        if ($clientId === null) {
            fwrite(STDERR, "Usage: kms:resume <client-id>\n");
            return 1;
        }

        $cfg = CryptoConfig::fromEnv()->kmsConfig();
        if ($cfg === []) {
            fwrite(STDERR, "No KMS endpoints configured (set BLACKCAT_KMS_ENDPOINTS).\n");
            return 1;
        }

        $router = new KmsRouter($cfg, $this->logger);
        $router->release($clientId);
        echo "Resumed {$clientId}\n";
        return 0;
    }
}

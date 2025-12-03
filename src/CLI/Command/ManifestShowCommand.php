<?php
declare(strict_types=1);

namespace BlackCat\Crypto\CLI\Command;

use BlackCat\Crypto\Config\CryptoConfig;

final class ManifestShowCommand implements CommandInterface
{
    public function name(): string
    {
        return 'manifest:show';
    }

    public function description(): string
    {
        return 'Print loaded manifest (slots + rotation policies) or write it to disk.';
    }

    public function run(array $args): int
    {
        $env = $_ENV + $_SERVER;
        $manifestOverride = null;
        $outputPath = null;
        foreach ($args as $arg) {
            if (str_starts_with($arg, '--manifest=')) {
                $manifestOverride = substr($arg, 11);
            } elseif (str_starts_with($arg, '--output=')) {
                $outputPath = substr($arg, 9);
            } elseif (str_starts_with($arg, '--')) {
                fwrite(STDERR, "Unknown option {$arg}\n");
                return 1;
            }
        }

        if ($manifestOverride) {
            $env['BLACKCAT_CRYPTO_MANIFEST'] = $manifestOverride;
        }

        $config = CryptoConfig::fromEnv($env);
        $payload = [
            'manifest' => $config->manifestPath(),
            'slots' => $config->slots(),
            'rotation' => $config->rotationPolicies(),
        ];

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
        if ($outputPath) {
            file_put_contents($outputPath, $json);
            echo "Manifest exported to {$outputPath}\n";
        } else {
            echo $json;
        }
        return 0;
    }
}

<?php
declare(strict_types=1);

namespace BlackCat\Crypto\CLI\Command;

use Psr\Log\LoggerInterface;

final class KeyRotateCommand implements CommandInterface
{
    public function __construct(private readonly LoggerInterface $logger) {}

    public function name(): string
    {
        return 'key:rotate';
    }

    public function description(): string
    {
        return 'Generate fresh key material for a slot into a directory (rotation helper).';
    }

    public function run(array $args): int
    {
        [$options, $positionals] = $this->parseArgs($args);
        $slot = $positionals[0] ?? null;
        $dir = $positionals[1] ?? null;
        $format = strtolower((string)($options['format'] ?? 'raw'));
        $manifestPath = $options['manifest'] ?? getenv('BLACKCAT_CRYPTO_MANIFEST') ?: null;
        $length = $this->deriveLength($options, $manifestPath, $slot);

        if (!in_array($format, ['raw', 'hex', 'base64'], true)) {
            fwrite(STDERR, "Invalid format {$format}; use raw|hex|base64\n");
            return 1;
        }

        if ($slot === null || $dir === null) {
            fwrite(STDERR, "Usage: key:rotate <slot> <dir> [--length=32] [--format=raw|hex|base64] [--manifest=path]\n");
            return 1;
        }

        if ($length <= 0 || ($format === 'raw' && $length < 16)) {
            fwrite(STDERR, "Length must be positive" . ($format === 'raw' ? ' (>=16 bytes for raw output)' : '') . "\n");
            return 1;
        }

        if (!is_dir($dir) && !@mkdir($dir, 0770, true) && !is_dir($dir)) {
            fwrite(STDERR, "Unable to create directory: {$dir}\n");
            return 1;
        }

        $bytes = random_bytes($length);
        [$content, $ext] = $this->formatKey($bytes, $format);
        $file = $this->buildFilename($dir, $slot, $ext);

        if (file_put_contents($file, $content) === false) {
            $this->logger->error('key-rotate-write-failed', ['slot' => $slot, 'file' => $file]);
            fwrite(STDERR, "Failed to write key file\n");
            return 1;
        }
        @chmod($file, 0600);
        $this->logger->info('key-rotated', ['slot' => $slot, 'file' => $file, 'length' => $length, 'format' => $format]);
        echo "Rotated {$slot} -> {$file} ({$length} bytes, {$format})\n";
        return 0;
    }

    /**
     * @param array<int,string> $args
     * @return array{0:array<string,mixed>,1:array<int,string>}
     */
    private function parseArgs(array $args): array
    {
        $options = [];
        $positionals = [];
        foreach ($args as $arg) {
            if (str_starts_with($arg, '--')) {
                [$key, $value] = array_pad(explode('=', substr($arg, 2), 2), 2, true);
                $options[$key] = $value;
            } else {
                $positionals[] = $arg;
            }
        }
        return [$options, $positionals];
    }

    private function buildFilename(string $dir, string $slot, string $ext = 'key'): string
    {
        $safeSlot = preg_replace('~[^A-Za-z0-9_.-]+~', '_', $slot) ?: 'slot';
        $timestamp = date('Ymd_His');
        $suffix = substr(bin2hex(random_bytes(4)), 0, 8);
        return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . "{$safeSlot}_{$timestamp}_{$suffix}.{$ext}";
    }

    /**
     * @return array{0:string,1:string}
     */
    private function formatKey(string $bytes, string $format): array
    {
        return match ($format) {
            'hex' => [bin2hex($bytes), 'hex'],
            'base64' => [base64_encode($bytes), 'b64'],
            default => [$bytes, 'key'],
        };
    }

    /**
     * @param array<string,mixed> $options
     */
    private function deriveLength(array $options, ?string $manifestPath, ?string $slot): int
    {
        if (isset($options['length']) && is_numeric($options['length'])) {
            return (int)$options['length'];
        }

        if ($manifestPath && $slot && is_file($manifestPath)) {
            $manifest = json_decode((string)file_get_contents($manifestPath), true);
            $slotDef = $manifest['slots'][$slot] ?? null;
            if (is_array($slotDef) && isset($slotDef['length']) && is_int($slotDef['length'])) {
                return $slotDef['length'];
            }
        }

        return 32;
    }
}

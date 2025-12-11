<?php
declare(strict_types=1);

namespace BlackCat\Crypto\CLI\Command;

final class ManifestValidateCommand implements CommandInterface
{
    public function name(): string
    {
        return 'manifest:validate';
    }

    public function description(): string
    {
        return 'Validate a manifest structure and report issues.';
    }

    public function run(array $args): int
    {
        $json = false;
        $path = null;
        foreach ($args as $arg) {
            if ($arg === '--json') {
                $json = true;
                continue;
            }
            if (!str_starts_with($arg, '--')) {
                $path = $arg;
            }
        }

        if ($path === null) {
            fwrite(STDERR, "Usage: manifest:validate <manifest.json> [--json]\n");
            return 1;
        }

        [$valid, $issues] = $this->validateManifest($path);
        if ($json) {
            echo json_encode(['valid' => $valid, 'issues' => $issues], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
        } else {
            if ($valid) {
                echo "Manifest OK: {$path}\n";
            } else {
                echo "Manifest issues ({$path}):\n";
                foreach ($issues as $issue) {
                    echo " - {$issue}\n";
                }
            }
        }

        return $valid ? 0 : 1;
    }

    /**
     * @return array{0:bool,1:array<int,string>}
     */
    private function validateManifest(string $path): array
    {
        if (!is_file($path)) {
            return [false, ["Manifest not found: {$path}"]];
        }
        $data = json_decode((string)file_get_contents($path), true);
        if (!is_array($data)) {
            return [false, ['Manifest is not valid JSON']];
        }
        $issues = [];
        if (isset($data['version']) && (!is_int($data['version']) || $data['version'] < 1)) {
            $issues[] = 'version must be a positive integer when present';
        }

        $slots = $data['slots'] ?? null;
        if (!is_array($slots) || $slots === []) {
            $issues[] = 'slots must be a non-empty object/dictionary';
            $slots = [];
        }
        $seenContexts = [];
        $allowedTypes = ['aes', 'aead', 'hmac', 'hybrid', 'wrap', 'rsa'];
        foreach ($slots as $slotName => $definition) {
            if (!is_array($definition)) {
                $issues[] = "slot {$slotName} is not an object";
                continue;
            }
            $type = $definition['type'] ?? null;
            if (!is_string($type) || $type === '') {
                $issues[] = "slot {$slotName} is missing type";
            } elseif (!in_array($type, $allowedTypes, true)) {
                $issues[] = "slot {$slotName} has unsupported type '{$type}'";
            }

            $length = $definition['length'] ?? null;
            if (in_array($type, ['aes', 'aead', 'hmac'], true)) {
                if (!is_int($length) || $length < 16 || $length > 256) {
                    $issues[] = "slot {$slotName} length must be 16-256 for type {$type}";
                }
            }

            $contexts = $definition['contexts'] ?? null;
            if (!is_array($contexts) || $contexts === []) {
                $issues[] = "slot {$slotName} must declare contexts";
            } else {
                foreach ($contexts as $ctx) {
                    if (!is_string($ctx) || trim($ctx) === '') {
                        $issues[] = "slot {$slotName} has invalid context entry";
                        continue;
                    }
                    $seenContexts[] = $ctx;
                }
            }

            if (isset($definition['kms'])) {
                if (!is_array($definition['kms'])) {
                    $issues[] = "slot {$slotName} kms must be an array";
                } else {
                    foreach ($definition['kms'] as $idx => $kms) {
                        if (!is_array($kms)) {
                            $issues[] = "slot {$slotName} kms entry #{$idx} must be an object";
                            continue;
                        }
                        if (empty($kms['id']) || !is_string($kms['id'])) {
                            $issues[] = "slot {$slotName} kms entry #{$idx} missing id";
                        }
                        if (isset($kms['weight']) && (!is_int($kms['weight']) || $kms['weight'] <= 0)) {
                            $issues[] = "slot {$slotName} kms entry #{$idx} weight must be positive int";
                        }
                        if (isset($kms['contexts']) && is_array($kms['contexts'])) {
                            foreach ($kms['contexts'] as $ctx) {
                                if (!is_string($ctx) || trim($ctx) === '') {
                                    $issues[] = "slot {$slotName} kms entry #{$idx} has invalid context";
                                }
                            }
                        }
                    }
                }
            }
        }

        $rotation = $data['rotation'] ?? [];
        if (!is_array($rotation)) {
            $issues[] = 'rotation must be an object/dictionary';
            $rotation = [];
        }
        foreach ($rotation as $ctx => $rule) {
            if (!is_array($rule)) {
                $issues[] = "rotation rule {$ctx} must be an object";
                continue;
            }
            $hasAge = isset($rule['maxAgeSeconds']) && is_int($rule['maxAgeSeconds']) && $rule['maxAgeSeconds'] > 0;
            $hasItems = isset($rule['maxItems']) && is_int($rule['maxItems']) && $rule['maxItems'] > 0;
            if (!$hasAge && !$hasItems) {
                $issues[] = "rotation rule {$ctx} should define positive maxAgeSeconds or maxItems";
            }
            if (!in_array($ctx, $seenContexts, true)) {
                $issues[] = "rotation rule {$ctx} refers to unknown context";
            }
        }

        $dupContexts = $this->duplicates($seenContexts);
        foreach ($dupContexts as $dup) {
            $issues[] = "context {$dup} is declared in multiple slots";
        }

        return [count($issues) === 0, $issues];
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private function duplicates(array $values): array
    {
        $seen = [];
        $dups = [];
        foreach ($values as $val) {
            if (isset($seen[$val])) {
                $dups[$val] = true;
            } else {
                $seen[$val] = true;
            }
        }
        return array_keys($dups);
    }
}

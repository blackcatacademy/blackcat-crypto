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
        if (!isset($data['version']) || !is_int($data['version']) || $data['version'] < 1) {
            $issues[] = 'version is required and must be a positive integer';
        }

        $slots = $data['slots'] ?? null;
        if (!is_array($slots) || $slots === []) {
            $issues[] = 'slots must be a non-empty object/dictionary';
            $slots = [];
        }
        $seenContexts = [];
        $contextToSlot = [];
        $allowedTypes = ['aes', 'aead', 'hmac', 'hybrid', 'wrap', 'rsa'];
        foreach ($slots as $slotName => $definition) {
            if (!is_string($slotName) || !preg_match('/^[a-z0-9._-]+$/', $slotName)) {
                $issues[] = "slot {$slotName} name must match /^[a-z0-9._-]+$/";
            }
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
            if ($type !== null) {
                if (in_array($type, ['aes', 'aead', 'hmac'], true)) {
                    if (!is_int($length) || $length < 16 || $length > 256 || $length % 8 !== 0) {
                        $issues[] = "slot {$slotName} length must be 16-256 and divisible by 8 for type {$type}";
                    }
                } elseif (in_array($type, ['wrap', 'hybrid'], true)) {
                    if (!is_int($length) || $length < 24) {
                        $issues[] = "slot {$slotName} length must be >=24 for type {$type}";
                    }
                } elseif ($type === 'rsa' && (!is_int($length) || $length < 2048)) {
                    $issues[] = "slot {$slotName} length must be >=2048 for type rsa";
                }
            }

            $contexts = $definition['contexts'] ?? null;
            if (!is_array($contexts) || $contexts === []) {
                $issues[] = "slot {$slotName} must declare contexts";
            } else {
                foreach ($contexts as $ctx) {
                    if (!is_string($ctx) || !preg_match('/^[a-z0-9._-]+$/', $ctx)) {
                        $issues[] = "slot {$slotName} has invalid context entry (must match /^[a-z0-9._-]+$/)";
                        continue;
                    }
                    $seenContexts[] = $ctx;
                    $contextToSlot[$ctx] = $slotName;
                }
            }

            $kmsWeightTotal = 0;
            $hasWeight = false;
            $seenKmsIds = [];
            if (isset($definition['kms'])) {
                if (!is_array($definition['kms'])) {
                    $issues[] = "slot {$slotName} kms must be an array";
                } else {
                    if (in_array($type, ['wrap', 'hybrid'], true) && $definition['kms'] === []) {
                        $issues[] = "slot {$slotName} requires at least one kms entry for type {$type}";
                    }
                    foreach ($definition['kms'] as $idx => $kms) {
                        if (!is_array($kms)) {
                            $issues[] = "slot {$slotName} kms entry #{$idx} must be an object";
                            continue;
                        }
                        $kmsId = $kms['id'] ?? null;
                        if (empty($kmsId) || !is_string($kmsId)) {
                            $issues[] = "slot {$slotName} kms entry #{$idx} missing id";
                        } elseif (isset($seenKmsIds[$kmsId])) {
                            $issues[] = "slot {$slotName} kms entry #{$idx} duplicate id '{$kmsId}'";
                        } else {
                            $seenKmsIds[$kmsId] = true;
                        }
                        $kmsType = $kms['type'] ?? 'http';
                        if (!in_array($kmsType, ['http', 'hsm', 'local'], true)) {
                            $issues[] = "slot {$slotName} kms entry #{$idx} type must be http|hsm|local";
                        }
                        if (isset($kms['weight'])) {
                            $hasWeight = true;
                            if (!is_int($kms['weight']) || $kms['weight'] <= 0) {
                                $issues[] = "slot {$slotName} kms entry #{$idx} weight must be positive int";
                            } else {
                                $kmsWeightTotal += $kms['weight'];
                            }
                        }
                        if (isset($kms['contexts']) && is_array($kms['contexts'])) {
                            foreach ($kms['contexts'] as $ctx) {
                                if (!is_string($ctx) || !preg_match('/^[a-z0-9._-]+$/', $ctx)) {
                                    $issues[] = "slot {$slotName} kms entry #{$idx} has invalid context";
                                } elseif (!in_array($ctx, $contexts ?? [], true)) {
                                    $issues[] = "slot {$slotName} kms entry #{$idx} context {$ctx} not in slot contexts";
                                }
                            }
                        } elseif (isset($kms['contexts']) && !is_array($kms['contexts'])) {
                            $issues[] = "slot {$slotName} kms entry #{$idx} contexts must be an array when present";
                        }
                    }
                    if ($hasWeight && $kmsWeightTotal !== 100) {
                        $issues[] = "slot {$slotName} kms weights must sum to 100 when provided";
                    }
                }
            } elseif (in_array($type, ['wrap', 'hybrid'], true)) {
                $issues[] = "slot {$slotName} requires kms configuration for type {$type}";
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

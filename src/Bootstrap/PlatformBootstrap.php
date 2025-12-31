<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Bootstrap;

use BlackCat\Crypto\Config\CryptoConfig;
use BlackCat\Crypto\CryptoManager;
use Psr\Log\LoggerInterface;

/**
 * One-call bootstrap helper for application repositories.
 *
 * - Boots {@see CryptoManager} from env (manifest + keys).
 * - If present, initializes `blackcat-core` engines so they delegate to the CoreCryptoBridge.
 * - If present, wires optional `blackcat-database` ingress hooks (gateway factory).
 */
final class PlatformBootstrap
{
    /**
     * @param array{
     *   keys_dir?:string,
     *   manifest?:string,
     *   logger?:mixed,
     *   strict?:bool,
     *   init_core?:bool,
     *   init_database?:bool,
     *   db_encryption_map?:string|null,
     *   db_gateway_factory?:mixed,
     * } $options
     */
    public static function boot(array $options = []): CryptoManager
    {
        $strict = (bool)($options['strict'] ?? true);
        $logger = $options['logger'] ?? null;
        if ($logger !== null && !$logger instanceof LoggerInterface) {
            throw new \InvalidArgumentException('PlatformBootstrap: logger must implement LoggerInterface');
        }

        $env = array_merge((array)getenv(), $_ENV, $_SERVER);

        $keysDir = $options['keys_dir'] ?? ($env['BLACKCAT_KEYS_DIR'] ?? $env['APP_KEYS_DIR'] ?? null);
        if (is_string($keysDir) && $keysDir !== '') {
            $env['BLACKCAT_KEYS_DIR'] = $keysDir;
        }

        $manifest = $options['manifest'] ?? ($env['BLACKCAT_CRYPTO_MANIFEST'] ?? null);
        if (is_string($manifest) && $manifest !== '') {
            $env['BLACKCAT_CRYPTO_MANIFEST'] = $manifest;
        }

        $crypto = CryptoManager::boot(CryptoConfig::fromEnv($env), $logger);

        if (($options['init_core'] ?? true) && class_exists('\\BlackCat\\Core\\Security\\Crypto')) {
            $keysDirArg = is_string($keysDir) && $keysDir !== '' ? $keysDir : null;
            try {
                /** @phpstan-ignore-next-line optional dependency */
                \BlackCat\Core\Security\Crypto::initFromKeyManager($keysDirArg, $logger);
            } catch (\Throwable $e) {
                if ($strict) {
                    throw $e;
                }
            }
        }

        if (($options['init_core'] ?? true) && class_exists('\\BlackCat\\Core\\Security\\FileVault') && is_string($keysDir) && $keysDir !== '') {
            try {
                /** @phpstan-ignore-next-line optional dependency */
                \BlackCat\Core\Security\FileVault::setKeysDir($keysDir);
            } catch (\Throwable $e) {
                if ($strict) {
                    throw $e;
                }
            }
        }

        if (($options['init_database'] ?? true) && class_exists('\\BlackCat\\Database\\Crypto\\IngressLocator')) {
            try {
                if (isset($options['db_gateway_factory']) && is_callable($options['db_gateway_factory'])) {
                    /** @phpstan-ignore-next-line optional dependency */
                    \BlackCat\Database\Crypto\IngressLocator::setGatewayFactory($options['db_gateway_factory']);
                }
            } catch (\Throwable $e) {
                if ($strict) {
                    throw $e;
                }
            }
        }

        return $crypto;
    }
}

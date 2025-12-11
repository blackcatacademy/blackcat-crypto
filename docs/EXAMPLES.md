# Blackcat Crypto – Quick Examples

## Encrypt/Decrypt (PHP)
```php
use BlackCat\Crypto\CryptoManager;
use BlackCat\Crypto\Config\CryptoConfig;
use Monolog\Logger;

$config = CryptoConfig::fromEnv();
$crypto = new CryptoManager($config, new Logger('crypto'));

$ciphertext = $crypto->encrypt('hello', ['context' => 'demo']);
$plaintext = $crypto->decrypt($ciphertext, ['context' => 'demo']);
```

## Validate manifest
```bash
BLACKCAT_CRYPTO_CONFIG=./crypto.yaml \
  php bin/crypto manifest:validate ./manifests/keys.yaml
```

## Rotate keys (dry run)
```bash
php bin/crypto key:rotate --manifest ./manifests/keys.yaml --dry-run
```

## Export telemetry
- JSON: `php bin/crypto metrics:export`
- Prometheus: `php bin/crypto metrics:export prom`
- OTLP/JSON: `php bin/crypto metrics:export otel`

## Intent telemetry
```bash
# enable intents in your bootstrap
BlackCat\Crypto\Telemetry\IntentCollector::global(new IntentCollector());

# then export
php bin/crypto telemetry:intents --format=otel --limit 10
```

## Governance auto-approval API
```bash
curl -X POST https://yourdomain/governance.php \
  -H 'Content-Type: application/json' \
  -d '{"tenant":"acme","sensitivity":"low","amount":500,"reason":"report export"}'
```

## Wrap queue
```bash
# enqueue wrap jobs from manifest
php bin/crypto wrap:queue --manifest ./manifests/keys.yaml

# check status/backlog
php bin/crypto wrap:status
```

## CI-aware telemetry
```bash
# pass CI env so DB hooks tag build info
GITHUB_ACTIONS=true GITHUB_RUN_ID=12345 \
  php bin/crypto metrics:export otel
```

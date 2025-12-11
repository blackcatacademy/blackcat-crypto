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

Environment toggles:

- `GOV_MAX_AUTO` (default `10000`) / `GOV_MAX_SENSITIVITY` (default `low`)
- `GOV_RATE_BURST` (default `50`) / `GOV_RATE_WINDOW` seconds (default `60`)
- `GOV_TENANT_LIMITS_JSON` e.g. `{"acme":{"max_amount":2000,"max_sensitivity":"medium"}}`

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

## KMS client config (HTTP)
```yaml
kms:
  - id: primary-http
    type: http
    base_uri: https://kms.example.com
    bearer: "${KMS_BEARER_TOKEN}"
    basic:
      user: "${KMS_USER}"
      pass: "${KMS_PASS}"
    headers:
      X-Tenant: acme
    ssl:
      ca: /etc/ssl/certs/ca.pem
      cert: /etc/ssl/certs/client.pem
      key: /etc/ssl/private/client.key
      verify_peer: true
    timeouts:
      connect: 2
      read: 5
```

## KMS client config (HSM)
```yaml
kms:
  - id: pci-hsm
    type: hsm
    endpoint: tcp://10.0.0.5:9000
    allow_ciphers: [aes-256-gcm, aes-192-gcm]
    tag_length: 16   # validated: must be 8..32
```

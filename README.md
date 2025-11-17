# BlackCat Crypto

Modulární šifrovací engine poskytující jednotné rozhraní pro veškerou práci s citlivými daty v ekosystému BlackCat. Cílem je, aby ostatní repozitáře (database, sync, auth…) nikdy nemusely řešit klíče, HMAC ani interakce s KMS – vše probíhá přes zdejší `CryptoManager`.

## Klíčové vlastnosti

- **Vícevrstvé šifrování** – každé tajemství je zabaleno lokálním AEAD klíčem (XChaCha20-Poly1305) a následně přebaleno náhodně vybraným KMS konektorem (double envelope). Bez obou vrstev není možné data dešifrovat.
- **Oddělené klíče pro každé použití** – HMAC, AEAD, derivace saltu i podpisy používají samostatný key-slot s vlastní historií/rotací.
- **Rotace bez re-encryptu** – staré záznamy se rewrapují asynchronně (KeyWrapQueue). Podporuje „wrap-to-new“ i „just-in-time“ rotace pro velké objemy.
- **Quantum-era readiness** – přepínatelné AEAD pluginy (`BLACKCAT_CRYPTO_AEAD=xchacha|hybrid`). Hybridní režim (Kyber+AES-GCM SIV) je připravený pro budoucí PQC rollout.
- **Centralizované HMACy** – `HmacService` vytváří a ověřuje značky pro libovolné use-cases (API requesty, CSRF, databázové hash sloupce) s podporou více klíčů a lazy rotace.
- **Asynchronní KMS routing** – `KmsRouter` volí „náhodný“ KMS backend dle politik (geo, compliance, váha) a ukládá metadata, která BlackCat Database už umí ukládat (tabulky `kms_wraps`, `kms_hosts` atd.).
- **Pohodlné integrace** – jednoduché fasády `CryptoManager::encryptContext('users.pii', $plaintext)` nebo `HmacService::sign('email-reset', $payload)` pro konzumenty. Žádná práce s klíči v cílových repozitářích.
- **Rotace bez bolesti** – `Queue\RotationCoordinator` spolu s wrap queue umožní rewrap (rotaci) citlivých dat asynchronně bez dopadu na aplikace.
- **Observabilita a governance** – wrap queue lze persistovat (`FileWrapQueue`, `BLACKCAT_CRYPTO_WRAP_QUEUE=file:///path`) a CLI/telemetry příkazy (`wrap:queue`, `metrics:export`) poskytují JSON i Prometheus metriky o backlogu a zdraví KMS clusteru.

## Struktura repozitáře

```
blackcat-crypto/
├── src/
│   ├── Contracts/      # rozhraní (KeyResolver, KmsClient…)
│   ├── Keyring/        # KeyRegistry, rotace, sloty
│   ├── AEAD/           # AEAD provider + adaptery
│   ├── Hmac/           # HMAC služby a validace
│   ├── Kms/            # router, context, metadata tracking
│   ├── Queue/          # úlohy na pozadí (wrap/rotate)
│   ├── Support/        # DTO + helpers (Hex, Encoding, SecureBuffer)
│   └── CryptoManager.php
├── docs/ROADMAP.md
├── README.md
├── composer.json
└── tests/
```

## Rychlý start

```bash
composer install
composer test

export BLACKCAT_KMS_ENDPOINTS='[{"id":"local-kms","endpoint":"http://127.0.0.1:8081","token":"local-dev"}]'
export BLACKCAT_CRYPTO_WRAP_QUEUE='file:///var/lib/blackcat/wrap.queue'
php bin/crypto key:generate --slot=data-aead
php bin/crypto encrypt --context="users.ssn" --stdin
php bin/crypto wrap:queue status --limit 5
```

Knihovnu pak použiješ v jiném repu:

```php
use BlackCat\Crypto\CryptoManager;
use BlackCat\Crypto\Config\CryptoConfig;
use BlackCat\Crypto\Queue\InMemoryWrapQueue;
use BlackCat\Crypto\Queue\RotationCoordinator;

$queue = new InMemoryWrapQueue();
$crypto = CryptoManager::boot(CryptoConfig::fromEnv())->withWrapQueue($queue);
$envelope = $crypto->encryptContext('users.pii', $plaintext);  // double-wrapped
store_in_db($envelope->encode());
$plain = $crypto->decryptContext('users.pii', $envelope->encode());

// naplánovat rewrap (např. po rotaci klíče)
$rotation = new RotationCoordinator($crypto, $queue, function (string $context, $newEnvelope) {
    store_in_db($newEnvelope->encode());
});
$rotation->schedule($envelope);
$rotation->process();
```

### Testy

```
composer test
```

V testech používáme `LoopbackKmsClient`, takže lze verifikovat AEAD i double-wrap bez skutečného KMS.

### CLI

```
php bin/crypto help
php bin/crypto key:generate users.pii keys/users.pii_v1.key
php bin/crypto wrap:status storage/envelopes/123.json
php bin/crypto kms:diag
php bin/crypto wrap:queue status --limit 10
php bin/crypto wrap:queue run --limit 25 --dump-dir=/tmp/rewrap
php bin/crypto metrics:export prom
php bin/crypto telemetry:sse --interval=5
php bin/crypto kms:watchdog --interval=30
```

CLI obsahuje generování klíčů, inspekci obálek, diagnostiku KMS, správu wrap queue a export metrik (JSON i Prometheus).

### Wrap queue & telemetry

- Nastav `BLACKCAT_CRYPTO_WRAP_QUEUE` na `memory` (pro vývoj) nebo `file:///var/lib/blackcat/wrap.queue` pro persistentní frontu (`FileWrapQueue`).
- Při nasazení rewrap jobu spusť `php bin/crypto wrap:queue run --limit 50 --dump-dir=/data/rewrap` a výsledné obálky uložené v dump složce aplikuj zpět do DB.
- `php bin/crypto metrics:export prom` exportuje metriky (`blackcat_kms_*`, `blackcat_wrap_queue_*`) pro Prometheus scrape endpoint.
- `php bin/crypto telemetry:sse` nabídne Server-Sent Events feed, které lze přeposílat do `blackcat-observability` nebo interních dashboardů.
- `php bin/crypto kms:watchdog` pravidelně kontroluje zdraví KMS a automaticky vypíná nestabilní klienty (obnoví je jakmile health hlásí OK).

### Rewrap orchestrace z externích systémů

- `BlackCat\Crypto\Rotation\TenantRewrapOrchestrator` zvládne přijmout události z `blackcat-database`/`blackcat-database-sync` (změna schématu, tenant, region) a enqueue-nout wrap job pro odpovídající context.
- Snadno se tak propojí s `blackcat-orchestrator` – při migraci nebo compliance eventu se automaticky naplánuje rewrap bez manuálního zásahu.

## Další kroky

- detailní ROADMAP v `docs/ROADMAP.md`
- `blackcat-crypto-kms` poskytuje referenční KMS servery (HTTP daemon `bin/kms-http`) – `HttpKmsClient` na ně umí mluvit s Auth tokenem.
- `BLACKCAT_CRYPTO_ROTATION` (JSON) umožňuje definovat politiky:\
  `export BLACKCAT_CRYPTO_ROTATION='{"users.*":{"maxAgeSeconds":86400,"maxWraps":3}}'`

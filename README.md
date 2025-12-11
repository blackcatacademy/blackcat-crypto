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
- **Intent telemetry** – aplikace můžou publikovat „intents“ (druh požadavku/operace); `telemetry:intents` vrací jejich počty i poslední položky (JSON/Prometheus, metriku `blackcat_intents_total`).

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
php bin/crypto manifest:show --output=/tmp/manifest.json
php bin/crypto vault:diag storage/files/
php bin/crypto vault:migrate storage/files/foo.enc storage/files/foo.envelope
php bin/crypto vault:decrypt storage/files/foo.enc --output=/tmp/foo.txt
php bin/crypto metrics:export prom
php bin/crypto telemetry:sse --interval=5
php bin/crypto telemetry:intents --format=prom --limit=25
php bin/crypto kms:watchdog --interval=30
php bin/crypto kms:suspend hsm-primary 600
php bin/crypto kms:resume hsm-primary
php bin/crypto gov:assess --tenant=acme --sensitivity=low --amount=500
php bin/crypto vault:coverage var/ingress.ndjson --table --top=5
php bin/crypto manifest:validate contexts/core.json --json
php bin/crypto key:rotate app.hsm keys/
# agregace ze všech repozitářů (viz docs/COVERAGE-WORKFLOW.md)
./scripts/run-coverage-report.sh --table --top=5
```

CLI obsahuje generování/rotaci klíčů, inspekci obálek, diagnostiku KMS, správu wrap queue a export metrik (JSON i Prometheus). Manifest nástroje přibyly i pro validaci (`manifest:validate`). KMS lze operativně vyřadit/obnovit pomocí `kms:suspend` a `kms:resume` – užitečné pro incident runbooky nebo při plánované údržbě.

### Core Bridge (blackcat-core ↔️ blackcat-crypto)

`blackcat-core` nyní používá `BlackCat\Crypto\Bridge\CoreCryptoBridge`, takže třídy `Security\Crypto`, `Security\KeyManager` a `Security\FileVault` delegují šifrování/HMAC na `CryptoManager`. Výhody:

- jednotné klíče/rotace napříč core aplikacemi bez duálních implementací,
- `Crypto::encrypt()` vrací verzi 2 payload (obsahuje `key_id`), ale `decrypt()` stále rozpozná staré verze 1,
- CSRF HMACy se vydávají přes slot `core.hmac.csrf` → snadnější audit v `blackcat-crypto`.

Bridging se aktivuje automaticky po zavolání `Crypto::initFromKeyManager()` (Stačí mít nainstalovaný balík `blackcat-crypto`). Legacy projekty tak mohou postupně přecházet na nový engine bez přepisu kódu.

### Manifesty kryptografických kontextů

Repo `blackcat-crypto-manifests` obsahuje sdílené JSON manifesty (`contexts/*.json`). Nastav:

```bash
export BLACKCAT_CRYPTO_MANIFEST=../blackcat-crypto-manifests/contexts/core.json

# porovnej manifesty (např. CI)
php bin/crypto manifest:diff --from=contexts/core.json --to=../env/prod/manifest.json --json
```

`CryptoConfig::fromEnv()` tím automaticky načte všechny sloty/rotace, které pak používají `CryptoManager`, `CoreCryptoBridge` i SDK balíčky (`blackcat-crypto-js`, `blackcat-crypto-rust`). Stačí přidat nový kontext do manifestu a všechny repozitáře jej získají při dalším bootu, žádná duplicita konfigurace.

Aktuální novinky a seznam změn viz `docs/RELEASE_NOTES.md`.

#### Vault CLI toolkit

- `php bin/crypto vault:diag storage/secure/` – projde všechny `.enc` soubory, zkontroluje headers/metadata (verze, `key_id`, kontext) a vypíše případná varování. Umí `--json`, `--manifest`, `--fail-on-warn`.
- `php bin/crypto vault:report storage/secure/` – agreguje statistiky (`context`, `key_version`, chybějící metadata) a porovnává s manifestem – vhodné pro audit/policy coverage dashboardy.
- `php bin/crypto vault:migrate legacy/file.enc new/file.envelope` – přečte starý FileVault soubor (`.enc` + `.meta`), dešifruje ho pomocí `CoreCryptoBridge` a uloží čistý `Envelope` (double-envelope) zpět do cílové cesty. Hodí se pro postupnou migraci historických dat.
- `php bin/crypto vault:decrypt legacy/file.enc --output=/tmp/plain.txt` – dešifruje `.enc` payload a uloží plaintext pro audit/debug (využívá stejný manifest kontext).

### Wrap queue & telemetry

- Nastav `BLACKCAT_CRYPTO_WRAP_QUEUE` na `memory` (pro vývoj) nebo `file:///var/lib/blackcat/wrap.queue` pro persistentní frontu (`FileWrapQueue`).
- Při nasazení rewrap jobu spusť `php bin/crypto wrap:queue run --limit 50 --dump-dir=/data/rewrap` a výsledné obálky uložené v dump složce aplikuj zpět do DB.
- `php bin/crypto metrics:export prom` exportuje metriky (`blackcat_kms_*`, `blackcat_wrap_queue_*`) pro Prometheus scrape endpoint.
- `php bin/crypto telemetry:sse` nabídne Server-Sent Events feed, které lze přeposílat do `blackcat-observability` nebo interních dashboardů.
- `php bin/crypto kms:watchdog` pravidelně kontroluje zdraví KMS a automaticky vypíná nestabilní klienty (obnoví je jakmile health hlásí OK).
- `php bin/crypto kms:list [--json]` vypíše registrované KMS klienty, váhy, kontexty a případné suspendace.
- `php bin/crypto gov:assess --tenant=acme --sensitivity=low --amount=500` vyhodnotí, zda lze rozbalení/unwrap schválit automaticky (governance guardrail).

### Rewrap orchestrace z externích systémů

- `BlackCat\Crypto\Rotation\TenantRewrapOrchestrator` zvládne přijmout události z `blackcat-database`/`blackcat-database-sync` (změna schématu, tenant, region) a enqueue-nout wrap job pro odpovídající context.
- Snadno se tak propojí s `blackcat-orchestrator` – při migraci nebo compliance eventu se automaticky naplánuje rewrap bez manuálního zásahu.

## Další kroky

- detailní ROADMAP v `docs/ROADMAP.md`
- `blackcat-crypto-kms` poskytuje referenční KMS servery (HTTP daemon `bin/kms-http`) – `HttpKmsClient` na ně umí mluvit s Auth tokenem.
- `BLACKCAT_CRYPTO_ROTATION` (JSON) umožňuje definovat politiky:\
  `export BLACKCAT_CRYPTO_ROTATION='{"users.*":{"maxAgeSeconds":86400,"maxWraps":3}}'`

## Development (Docker-friendly)

- Requirements: PHP 8.3+, ext-sodium, Composer.
- Install deps + dev tools: `composer install`
- Run tests: `composer test`
- Static analysis: `composer stan`
- Docker build (optional): `docker build -t blackcat-crypto .`
- Run tests in container:
  ```bash
  docker run --rm -v $(pwd):/app -w /app blackcat-crypto vendor/bin/phpunit
  ```
- Or via compose: `docker-compose run --rm crypto`

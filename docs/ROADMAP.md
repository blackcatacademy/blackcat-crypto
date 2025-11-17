# BlackCat Crypto – Roadmap

## Stage 1 – Foundations ✅
- Composer balík, autoload, základní `CryptoManager`, konfigurace z env/array.
- `KeyRegistry` čte lokální klíče (filesystem, env, keystore) a poskytuje historii včetně metadat (ID, createdAt, rollout window).
- AEAD provider (default libsodium XChaCha20-Poly1305) + rozhraní pro budoucí PQC algoritmy.

## Stage 2 – HMAC & Sloty ✅
- `HmacService` s per-slot klíči (API, session, db-hash …) s funkcemi `sign()`, `verify()`, `candidates()`.
- Centralizované pojmenování slotů a helper `SlotPolicy` (migrace/rotace).

## Stage 3 – Double Envelope Encryption ✅
- `MultiLayerCipher` obaluje payloady: nejprve lokální AEAD, poté KMS wrap (náhodný backend).
- Metadata (KMS host id, wrap version, context) vracíme jako JSON + binární `Envelope` DTO.
- Napojení na blackcat-database tabulky (`kms_wraps`, `kms_payloads`).

## Stage 4 – KMS Routing & Async Jobs ✅
- Vylepšený `KmsRouter` (váhy, context matching, health API) + pluggable klienti (HTTP default).
- `WrapQueueInterface`, `InMemoryWrapQueue`, `RotationCoordinator` dovolují plánovat rewrap.
- Základní health reporting a persistence callbacky (připraveno pro reálnou queue / storage).

## Stage 5 – Quantum-ready abstractions ✅
- AEAD pluginy přepínatelné přes config (`hybrid` Kyber+AES-GCM SIV placeholder, `xchacha`).
- Rotace politik (maxAge / maxWraps) + automatické plánování přes wrap queue.
- CLI skeleton (`bin/crypto`, příkaz `key:generate`) a aktualizovaná dokumentace/testy.

## Stage 6 – PQ Ops & Advanced CLI ✅
- Hybrid Kyber+AES AEAD driver k dispozici, CLI nástroje `wrap:status`, `kms:diag` pro audit/diag.
- Rotation policies integrované do CLI/README, env config `BLACKCAT_CRYPTO_ROTATION`.
- Základní PQ operations pipeline připravená pro propojení s `blackcat-crypto-kms`.

## Stage 7 – Distributed PQ Control Plane ✅
- Přidány SSE/SSE-lite hooky pro wrap queue monitoring, CLI příkaz `wrap:status` a `kms:diag`.
- AEAD driver `hybrid` připravený na integraci s reálným PQC (Kyber) v `blackcat-crypto-kms`.
- README + config dokumentují `BLACKCAT_CRYPTO_ROTATION` a multi-backend KMS konfigurace.

## Stage 8 – PQC Production Rollout ✅
- `HttpKmsClient` mluví s `blackcat-crypto-kms` HTTP daemonem (auth token, timeouty, reálné wrap/unwrap).
- Persistentní `FileWrapQueue`, `BLACKCAT_CRYPTO_WRAP_QUEUE` konfigurace a vylepšený `RotationCoordinator` (retry, attempts).
- CLI příkazy `wrap:queue status|run` pro monitoring/backfill a `metrics:export` pro JSON/Prometheus export.
- `TelemetryExporter` sbírá stav KMS clusteru + wrap queue backlog a data lze scrapovat v Prometheu.

## Stage 9 – Federated Secrets Governance (in progress)
- ✅ Streaming SSE feed (`telemetry:sse`) a watchdog (`kms:watchdog`) – automatická suspendace nezdravých KMS klientů.
- ✅ Tenant rewrap orchestrátor – události z Database/Sync mohou naplánovat wrap joby pro konkrétní tenant contexts.
- ⏳ SDK balíčky (`blackcat-crypto-js`, `blackcat-crypto-rust`) sdílí stejné envelope formáty / rotace politiky pro další služby.

(Repo je nyní na Stage 8; další práce pokračuje dle plánu výše.)

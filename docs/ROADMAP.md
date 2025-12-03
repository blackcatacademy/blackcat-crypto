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

## Stage 9 – Federated Secrets Governance ✅
- Streaming SSE feed (`telemetry:sse`) a watchdog (`kms:watchdog`) – automatická suspendace nezdravých KMS klientů.
- Tenant rewrap orchestrátor – události z Database/Sync mohou naplánovat wrap joby pro konkrétní tenant contexts.
- CoreBridge (`BlackCat\Crypto\Bridge\CoreCryptoBridge`) sjednocuje `blackcat-core` (`Crypto.php`, `FileVault.php`, `KeyManager.php`) s `CryptoManagerem`, takže všechna core data používají totožné AEAD/HMAC sloty jako zbytek platformy.
- SDK balíčky (`blackcat-crypto-js`, `blackcat-crypto-rust`) sdílí envelope formáty + rotace politiky s centrálním enginem.

Repo je nyní na Stage 9.

## Stage 10 – Vault Streaming & Policy Mesh ✅
- `blackcat-core` FileVault streamuje přes `CryptoManager` (chunked encrypt/decrypt, audit trail). `.meta` a AUDIT logy nesou `key_id` i manifest kontext.
- Vault CLI trio `vault:diag`/`vault:report`/`vault:decrypt` pokrývá auditní scénáře (metadata coverage vs manifest, fail-on-warn, plaintext export).
- `vault:migrate` slouží k postupné migraci legacy `.enc` → double-envelope + wrap queue follow-up.
- Cross-repo policy mesh: manifesty (`blackcat-crypto-manifests`) sdílí kontexty pro `blackcat-core`, `blackcat-crypto`, `blackcat-crypto-js` i DB adapter.
- `blackcat-database-crypto` Stage 1 zakončena (transparentní šifrování při insert/update).

## Stage 11 – Data Plane Fusion (in progress)
- Transparentní hooky v `blackcat-database` repositories (registrace encryption mapy, linting + telemetry).
- `CryptoManager` publikuje “query intents” – metadata proudí do observability (traces/logs) a governance služeb.
- Self-service portal (napojený na `blackcat-governance`, `blackcat-support`) pro správu manifestů, approvals, regeneraci CLI/SDK artefaktů.
- Vault policy enforcement: `vault:report --fail-on-unused` + API/feeds do compliance dashboards.

## Stage 12 – Autonomous Compliance Mesh (planned)
- Automatizované enforcement runbooks: pokud manifest/DB driftuje, orchestrace spouští `vault:migrate` / wrap queue / ticketing.
- AI asistenti (`blackcat-ai`) navrhují nové contexty podle datových profilů, generují PRs do manifest repo.
- Cross-cloud KMS handshake – `blackcat-crypto-kms` i `blackcat-hsm` sdílí stejné manifesty + telemetry, což umožní zero-trust multi-cloud rotace.

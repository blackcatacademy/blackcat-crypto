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
- Implementováno: HSM shim (`HsmKmsClient`), CLI pro rotace klíčů (`key:rotate`), validátor manifestů (`manifest:validate`), KMS router umí preferovat HSM klienta a CLI `kms:list|suspend|resume` + `describe()` pokrytí, intent/metrics export do OpenTelemetry (`metrics:export --format otel`, `telemetry:intents --format otel`).
- Další na řadě: governanční API pro auto-aproval low-risk unwraps, rollout hooků v `blackcat-database-crypto` (lint + telemetry v CI), richer intent telemetry (action/context tagging) a archivace intent feedu.

## Stage 12 – Autonomous Compliance Mesh (planned)
- Automatizované enforcement runbooks: pokud manifest/DB driftuje, orchestrace spouští `vault:migrate` / wrap queue / ticketing.
- AI asistenti (`blackcat-ai`) navrhují nové contexty podle datových profilů, generují PRs do manifest repo.
- Cross-cloud KMS handshake – `blackcat-crypto-kms` i `blackcat-hsm` sdílí stejné manifesty + telemetry, což umožní zero-trust multi-cloud rotace.

## Stage 13 – Trustless Proofs & Customer Control (planned)
- Kryptografické auditní doklady: podepsané wrap/unwrap eventy a Merkle stromy nad KMS odpověďmi pro nezpochybnitelný audit.
- BYOK/CKMS režim: plnohodnotná správa klíčů zákazníkem (rotate, suspend, geo-fence) při zachování platformních manifestů.
- Hardening datové roviny: vzdálené ověřování klientů (attestation z HSM/TEE), „no-plaintext“ režim pro citlivé tenancy.

## Stage 14 – MPC / Threshold Fabric (exploratory)
- Experimentální threshold šifrování (Shamir / FROST) pro nejkritičtější klíče a recovery scénáře.
- Zřetězené politiky pro disaster recovery (air-gap KMS, odpojitelné rotace, geo-sealed wrap queue).
- Integrované kontrolní panely pro CISO/SRE: risk score klíčů, simulace selhání KMS a doporučené runbooky.

## Stage 15 – Attested Edge & BYOK at Scale (planned)
- Attestation-first klienti (TEE/HSM) pro edge workloady; politika vyžaduje ověření prostředí před wrap/unwrap.
- BYOK/BYO-KMS orchestrace: self-service registrace tenant KMS s automatickým health-check a rollback scénáři.
- Adaptive routing podle rizika (geo, cloud, tenant class) + real-time policy updates bez výpadku.

## Stage 16 – Zero-Touch Assurance (exploratory)
- Kryptografické „proof bundles“ (Merkle + podpis) pro každý wrap/unwrap/request – export do SIEM/forenzních nástrojů.
- Plně automatizované runbooky při incidentu: auto-fence KMS uzlů, přesměrování na zálohy, audit feed do governance.
- Remote kill-switch a „read-only“ režim pro nejrizikovější tenancy s řízeným návratem do plného provozu.

## Stage 17 – Privacy-Preserving Analytics (future)
- Volitelné HE/TEE kanály pro agregace bez dešifrování (počty, sumy, frekvence) – bezpečné feedy do analytics/AI.
- „Dual control“ dotazování: risk scoring + policy approval pro jakýkoli přístup k zašifrovaným datům.
- Automatizované rotace + rewrap na základě anomálií (ML model nad telemetry z KMS/queue).

## Stage 18 – Continuous Assurance & Certifications (future)
- Generování exportů pro SOC2/ISO/NIS2: důkazy o rotacích, KMS health, podpisy manifestů.
- „Live posture“ dashboard: crypto hygiene score, doporučení k hardeningu, simulace výpadků cloud KMS.
- Podpora regulovaných sektorů (fin/health/public) – předpřipravené politiky a reporting šablony.

## Stage 19 – Federated Privacy & Clean Rooms (future)
- Privacy-preserving collaboration: standardizované envelopes/tokeny pro clean-room výpočty a federované AI tréninky.
- FHE/SMPC experimenty pro vybrané metriky (počty, CTR, churn) s politikami, které definují risk/cost hranice.
- Cross-tenant policy mesh: koordinace rotací, wrap queue a attestací napříč partnery bez sdílení plaintextu.

## Stage 20 – Certified PQ & Multi-Cloud Resilience (future)
- Certifikační balíček pro PQ readiness (evidence o rotacích, attestace KMS/HSM, disaster runbooky) pro multi-cloud.
- Geo-distributed policy mesh: automatické failover/failback s atestačními důkazy, bez manuálních zásahů.
- Adaptive cost/risk engine: dynamicky volí algoritmy a routy (PQC vs hybrid) podle SLA, nákladů a compliance profilu.

## Stage 21 – Zero-Knowledge Control Plane (future)
- ZK důkazy pro policy enforcement: ověření, že wrap/unwrap proběhl dle politiky bez odhalení obsahu.
- ZK attestace klientů (kombinace attestation + ZK) pro citlivé tenancy; evidence o splnění požadavků bez leaků.
- „Prove-before-run“ mód pro nejrizikovější operace (např. export/unwrap), s auditováním do SIEM.

## Stage 22 – Quantum Resilience Benchmark Suite (future)
- Standardizované bench + test vectors pro PQ/hybrid AEAD a HMAC sloty, s publikačním scorecardem.
- Chaos/DR testy nad KMS routerem a wrap queue (latence, výpadky, útoky) s automatickým hardening doporučením.
- Publikované „trust levels“ per algoritmus/route, využitelné governance nástroji a SRE playbooky.

## Stage 23 – Policy-as-Code & Explainable Crypto (future)
- Policy-as-code hub: verifikovatelné policy balíčky (OPA/rego + ZK proofs) s impact analýzou před nasazením.
- Explainable crypto router: vysvětlení, proč byla použita konkrétní trasa/algoritmus, včetně nákladů a rizik.
- “Shadow routing” režim: testuje nové politiky/algoritmy paralelně a publikuje srovnávací metriky.

## Stage 24 – AI-Augmented Operations (future)
- AI asistenti pro incidenty: návrhy mitigací (reroute, rewrap, suspend client) s odhadovaným dopadem.
- Predictive scaling pro KMS/router podle telemetrie (load, latence, health) a SLA.
- Automatická tvorba runbooků a PRs do manifestů/politik na základě zjištěných anomálií.

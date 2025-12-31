# Troubleshooting

## Manifest issues

**Symptom:** `Manifest is not readable` / `Manifest is not valid JSON` / `slots must be a non-empty object`.

- Verify the env var points to an existing JSON file:
  - `BLACKCAT_CRYPTO_MANIFEST=/path/to/contexts/core.json`
- Validate it:
  - `blackcat crypto manifest:validate "$BLACKCAT_CRYPTO_MANIFEST"` (or `php bin/crypto …` without `blackcat-cli`)

## Keys dir not detected

**Symptom:** `CoreCryptoBridge requires readable keys_dir directory` or `Keys directory is not readable`.

- Ensure `BLACKCAT_KEYS_DIR` points to a real directory with read permission:
  - `export BLACKCAT_KEYS_DIR=./keys`
- Lint keys against the manifest:
  - `blackcat crypto keys:lint --manifest="$BLACKCAT_CRYPTO_MANIFEST" --keys-dir="$BLACKCAT_KEYS_DIR"`

## Wrong key length / invalid encoding

**Symptom:** `matching files exist but none are valid (decode/length)` or `invalid ... length mismatch`.

- Generate the correct key length for the slot:
  - `blackcat crypto key:rotate <slot> "$BLACKCAT_KEYS_DIR" --manifest="$BLACKCAT_CRYPTO_MANIFEST"`
- Remember:
  - `.key` files are **raw bytes** (length must match exactly).
  - `.hex` must decode to the exact slot length.
  - `.b64` must decode to the exact slot length.

## Env key values don’t work

**Symptom:** keys from `BC_KEY_*` are not picked up or decode fails.

- Use the `BC_KEY_<KEYNAME>_V<N>` naming (optionally add `_HEX|_B64|_RAW`):
  - `export BC_KEY_CRYPTO_KEY_V1="$(openssl rand -base64 32)"`
  - `export BC_KEY_CRYPTO_KEY_V2_HEX="$(openssl rand -hex 32)"`

## HMAC verification fails after rotation

**Symptom:** old rows become unverifiable after rotating HMAC keys.

- Store and use the signing key id (`*_key_version`) and verify via the fast-path:
  - `CryptoManager::verifyHmacWithKeyId($slot, $message, $sig, $keyId)`
- If you must lookup without knowing the key id/version, compute candidates and query via `IN (...)`:
  - `CryptoManager::hmacCandidates($slot, $message)`

## “KMS not used” / local metadata only

**Symptom:** envelopes show `"client":"local"` in KMS metadata.

- That means no KMS client matched the context, or no KMS was configured.
- Provide `BLACKCAT_KMS_ENDPOINTS` (JSON array) and (optionally) `contexts` patterns per client.

## CI differences

**Symptom:** things work locally but fail in CI.

- Ensure CI has access to the same manifest and keys (or generates them deterministically).
- Use `keys:lint` in your application repos as an early gate.

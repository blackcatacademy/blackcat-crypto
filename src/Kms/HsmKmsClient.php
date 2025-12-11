<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Kms;

use BlackCat\Crypto\Contracts\KmsClientInterface;
use BlackCat\Crypto\Support\Payload;
use RuntimeException;

/**
 * Lightweight “HSM” adapter that keeps a local symmetric key and speaks the same
 * contract as remote KMS clients. Useful for dev/test or when integrating with
 * on-prem HSMs through a PKCS#11 bridge.
 */
final class HsmKmsClient implements KmsClientInterface
{
    public function __construct(private readonly array $config)
    {
    }

    public function id(): string
    {
        return (string)($this->config['id'] ?? 'hsm-kms');
    }

    public function wrap(string $context, Payload $payload): array
    {
        $key = $this->loadKey();
        $cipher = $this->cipher();
        $nonce = random_bytes(12);
        $aad = $this->aad();
        $tagLength = $this->tagLength($cipher);
        $tag = null;

        $ciphertext = openssl_encrypt(
            $payload->ciphertext,
            $cipher,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad,
            $tagLength
        );
        if ($ciphertext === false) {
            throw new RuntimeException('HSM wrap failed for context ' . $context);
        }

        $meta = [
            'ciphertext' => base64_encode($ciphertext),
            'nonce' => base64_encode($nonce),
            'keyId' => $this->id(),
            'innerNonce' => base64_encode($payload->nonce),
            'cipher' => $cipher,
        ];
        if ($tag !== null) {
            $meta['tag'] = base64_encode($tag);
        }

        return $meta;
    }

    public function unwrap(string $context, array $metadata): Payload
    {
        $key = $this->loadKey();
        $cipher = (string)($metadata['cipher'] ?? $this->cipher());
        $ciphertext = base64_decode((string)($metadata['ciphertext'] ?? ''), true);
        $nonce = base64_decode((string)($metadata['nonce'] ?? ''), true);
        $tag = array_key_exists('tag', $metadata) ? base64_decode((string)$metadata['tag'], true) : null;
        if ($ciphertext === false || $nonce === false) {
            throw new RuntimeException('HSM unwrap metadata invalid for ' . $context);
        }
        $aad = $this->aad();
        $plaintext = openssl_decrypt(
            $ciphertext,
            $cipher,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag ?: '',
            $aad
        );
        if ($plaintext === false) {
            throw new RuntimeException('HSM unwrap failed for context ' . $context);
        }
        $innerNonce = base64_decode((string)($metadata['innerNonce'] ?? ''), true) ?: '';
        $keyId = (string)($metadata['keyId'] ?? $this->id());
        return new Payload(ciphertext: $plaintext, nonce: $innerNonce, keyId: $keyId, meta: ['client' => $this->id(), 'cipher' => $cipher]);
    }

    public function health(): array
    {
        return [
            'client' => $this->id(),
            'status' => 'ok',
            'origin' => 'local-hsm',
        ];
    }

    private function loadKey(): string
    {
        $secret = (string)($this->config['secret'] ?? '');
        if ($secret === '') {
            throw new RuntimeException('HsmKmsClient requires a base64 secret.');
        }
        $bytes = base64_decode($secret, true);
        if ($bytes === false) {
            throw new RuntimeException('HsmKmsClient secret must be base64-encoded.');
        }
        $minLen = (int)($this->config['key_bytes'] ?? 32);
        if (strlen($bytes) < $minLen) {
            throw new RuntimeException(sprintf('HsmKmsClient secret must be at least %d bytes.', $minLen));
        }
        return substr($bytes, 0, $minLen);
    }

    private function cipher(): string
    {
        $cipher = (string)($this->config['cipher'] ?? 'aes-256-gcm');
        if (!in_array($cipher, openssl_get_cipher_methods(), true)) {
            throw new RuntimeException('Cipher ' . $cipher . ' is not available.');
        }
        return $cipher;
    }

    private function tagLength(string $cipher): int
    {
        if (!$this->isAeadCipher($cipher)) {
            return 0;
        }
        return (int)($this->config['tag_length'] ?? 16);
    }

    private function isAeadCipher(string $cipher): bool
    {
        return stripos($cipher, 'gcm') !== false || stripos($cipher, 'ccm') !== false;
    }

    private function aad(): string
    {
        return (string)($this->config['aad'] ?? '');
    }
}

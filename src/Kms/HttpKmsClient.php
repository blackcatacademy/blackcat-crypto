<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Kms;

use BlackCat\Crypto\Contracts\KmsClientInterface;
use BlackCat\Crypto\Support\Payload;
use RuntimeException;

final class HttpKmsClient implements KmsClientInterface
{
    public function __construct(private readonly array $config)
    {
    }

    public function id(): string
    {
        return (string)($this->config['id'] ?? $this->config['endpoint'] ?? 'http-kms');
    }

    public function wrap(string $context, Payload $payload): array
    {
        $req = [
            'context' => $context,
            'payload' => base64_encode($payload->ciphertext),
            'nonce' => base64_encode($payload->nonce),
            'keyId' => $payload->keyId,
        ];
        $response = $this->request('/wrap', $req, 'POST');
        return $response + ['client' => $this->id()];
    }

    public function unwrap(string $context, array $metadata): Payload
    {
        $resp = $this->request('/unwrap', [
            'context' => $context,
            'payload' => $metadata['ciphertext'] ?? '',
            'nonce' => $metadata['nonce'] ?? '',
            'keyId' => $metadata['keyId'] ?? '',
        ]);
        return new Payload(
            ciphertext: base64_decode((string)$resp['payload'], true) ?: '',
            nonce: (string)($resp['nonce'] ?? ''),
            keyId: (string)($resp['keyId'] ?? ''),
        );
    }

    public function health(): array
    {
        return $this->request('/healthz', [], 'GET');
    }

    /** @return array<string,mixed> */
    private function request(string $path, array $body = [], string $method = 'POST'): array
    {
        $endpoint = rtrim((string)($this->config['endpoint'] ?? ''), '/');
        if ($endpoint === '') {
            throw new RuntimeException('HttpKmsClient requires endpoint');
        }
        $url = $endpoint . $path;
        $payload = $method === 'GET'
            ? ''
            : json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($payload === false) {
            throw new RuntimeException('Unable to encode KMS payload.');
        }
        $headers = [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: BlackCatCrypto/1.0',
        ];
        if (!empty($this->config['token'])) {
            $headers[] = 'Authorization: Bearer ' . $this->config['token'];
        }
        $timeout = max(1, (int)($this->config['timeout'] ?? 5));
        [$status, $response] = $this->sendRequest($url, $method, $payload, $headers, $timeout);
        $data = json_decode($response, true);
        if (!is_array($data)) {
            throw new RuntimeException('Invalid response from KMS: ' . $response);
        }
        if ($status >= 400) {
            $message = is_string($data['error'] ?? null) ? $data['error'] : ('HTTP ' . $status);
            throw new RuntimeException('KMS error: ' . $message);
        }
        return $data;
    }

    /**
     * @param list<string> $headers
     * @return array{0:int,1:string}
     */
    private function sendRequest(string $url, string $method, string $payload, array $headers, int $timeout): array
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            if ($method === 'GET') {
                curl_setopt($ch, CURLOPT_HTTPGET, true);
            } else {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            }
            $response = curl_exec($ch);
            if ($response === false) {
                $error = curl_error($ch);
                curl_close($ch);
                throw new RuntimeException('KMS request failed: ' . $error);
            }
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
            curl_close($ch);
            return [$status, $response];
        }

        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'content' => $method === 'GET' ? '' : $payload,
                'timeout' => $timeout,
                'ignore_errors' => true,
            ],
        ]);
        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            $error = error_get_last()['message'] ?? 'stream error';
            throw new RuntimeException('KMS request failed: ' . $error);
        }
        $statusLine = $http_response_header[0] ?? 'HTTP/1.1 200';
        preg_match('~\s(\d{3})\s~', $statusLine, $match);
        $status = isset($match[1]) ? (int)$match[1] : 0;
        return [$status, $response];
    }
}

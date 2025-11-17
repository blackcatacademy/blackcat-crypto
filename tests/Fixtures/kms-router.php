<?php
declare(strict_types=1);

$uri = $_SERVER['REQUEST_URI'] ?? '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$bodyRaw = file_get_contents('php://input') ?: '';
$body = json_decode($bodyRaw, true) ?: [];
header('Content-Type: application/json');

if ($uri !== '/healthz') {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($auth !== 'Bearer test-token') {
        http_response_code(401);
        echo json_encode(['error' => 'unauthorized']);
        return;
    }
}

switch ($uri) {
    case '/wrap':
        $payload = base64_decode((string)($body['payload'] ?? ''), true) ?: '';
        $cipher = strrev($payload);
        echo json_encode([
            'ciphertext' => base64_encode($cipher),
            'nonce' => $body['nonce'] ?? '',
            'keyId' => 'fixture-key',
        ]);
        break;
    case '/unwrap':
        $encoded = base64_decode((string)($body['payload'] ?? ''), true) ?: '';
        echo json_encode([
            'payload' => base64_encode(strrev($encoded)),
            'nonce' => $body['nonce'] ?? '',
            'keyId' => $body['keyId'] ?? 'fixture-key',
        ]);
        break;
    case '/healthz':
        echo json_encode(['status' => 'ok', 'timestamp' => time()]);
        break;
    default:
        http_response_code(404);
        echo json_encode(['error' => 'not-found', 'path' => $uri, 'method' => $method]);
}

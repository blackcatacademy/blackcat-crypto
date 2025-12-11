<?php
declare(strict_types=1);

use BlackCat\Crypto\Governance\GovernanceApprovalService;
use BlackCat\Crypto\Telemetry\IntentCollector;

require __DIR__ . '/../vendor/autoload.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Only POST allowed']);
    exit;
}

$input = file_get_contents('php://input');
$payload = json_decode($input ?: '{}', true);
if (!is_array($payload)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit;
}

$collector = IntentCollector::global();
if ($collector === null && getenv('BLACKCAT_CRYPTO_INTENTS')) {
    $collector = new IntentCollector();
    IntentCollector::global($collector);
}

$service = GovernanceApprovalService::fromEnv($collector);

$context = [
    'tenant' => $payload['tenant'] ?? null,
    'sensitivity' => $payload['sensitivity'] ?? null,
    'amount' => $payload['amount'] ?? null,
    'algorithm' => $payload['algorithm'] ?? null,
    'actor' => $payload['actor'] ?? null,
    'route' => $payload['route'] ?? null,
    'tags' => $payload['tags'] ?? null,
];

$decision = $service->assess($context);

echo json_encode([
    'decision' => $decision['decision'],
    'reason' => $decision['reason'],
    'meta' => [
        'timestamp' => time(),
        'limits' => $decision['meta']['limits'] ?? null,
        'rate' => $decision['meta']['rate'] ?? null,
    ],
]);

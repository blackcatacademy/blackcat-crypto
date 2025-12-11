<?php
declare(strict_types=1);

use BlackCat\Crypto\Governance\LowRiskApprovalService;

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

$maxAmountEnv = getenv('LOW_RISK_MAX_AMOUNT');
$maxSensitivityEnv = getenv('LOW_RISK_MAX_SENSITIVITY');
$maxAutoAmount = $maxAmountEnv !== false ? (int)$maxAmountEnv : 10_000;
$maxSensitivity = $maxSensitivityEnv !== false ? (string)$maxSensitivityEnv : 'low';
$tenantLimitsEnv = getenv('LOW_RISK_TENANT_LIMITS');
$tenantLimits = [];
if ($tenantLimitsEnv) {
    $decoded = json_decode($tenantLimitsEnv, true);
    if (is_array($decoded)) {
        $tenantLimits = $decoded;
    }
}
$burst = getenv('LOW_RISK_RATE_BURST');
$window = getenv('LOW_RISK_RATE_WINDOW');
$service = new LowRiskApprovalService(
    maxAutoAmount: $maxAutoAmount,
    maxSensitivity: $maxSensitivity,
    tenantLimits: $tenantLimits,
    defaultBurst: $burst !== false ? (int)$burst : 50,
    defaultWindowSeconds: $window !== false ? (int)$window : 60
);

$context = [
    'tenant' => $payload['tenant'] ?? null,
    'sensitivity' => $payload['sensitivity'] ?? null,
    'amount' => $payload['amount'] ?? null,
    'algorithm' => $payload['algorithm'] ?? null,
    'actor' => $payload['actor'] ?? null,
    'route' => $payload['route'] ?? null,
    'tags' => $payload['tags'] ?? null,
];

$decision = $service->assessUnwrap($context);

echo json_encode([
    'decision' => $decision['decision'],
    'reason' => $decision['reason'],
    'meta' => [
        'max_auto_amount' => $maxAutoAmount,
        'max_sensitivity' => $maxSensitivity,
        'timestamp' => time(),
        'limits' => $decision['meta']['limits'] ?? null,
        'rate' => $decision['meta']['rate'] ?? null,
    ],
]);

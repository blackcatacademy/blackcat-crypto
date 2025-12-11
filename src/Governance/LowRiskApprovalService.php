<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Governance;

/**
 * Lightweight governance helper: decides whether an unwrap/decrypt operation
 * can auto-approve or must be escalated.
 */
final class LowRiskApprovalService
{
    public function __construct(
        private int $maxAutoAmount = 10_000,
        private string $maxSensitivity = 'low'
    ) {
    }

    /**
     * @param array<string,mixed> $context
     * @return array{decision:string,reason:string}
     */
    public function assessUnwrap(array $context): array
    {
        $sensitivity = strtolower((string)($context['sensitivity'] ?? 'unknown'));
        $amount = (int)($context['amount'] ?? 0);
        $tenant = (string)($context['tenant'] ?? 'unknown');

        if ($sensitivity === 'low' || ($sensitivity === $this->maxSensitivity && $amount <= $this->maxAutoAmount)) {
            return [
                'decision' => 'approve',
                'reason' => sprintf('Auto-approved: tenant=%s sensitivity=%s amount=%d', $tenant, $sensitivity, $amount),
            ];
        }

        return [
            'decision' => 'review',
            'reason' => sprintf('Requires approval: tenant=%s sensitivity=%s amount=%d', $tenant, $sensitivity, $amount),
        ];
    }
}

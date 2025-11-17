<?php
declare(strict_types=1);

namespace BlackCat\Crypto\CLI\Command;

interface CommandInterface
{
    public function name(): string;
    public function description(): string;
    public function run(array $args): int;
}

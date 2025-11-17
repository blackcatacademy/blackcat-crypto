<?php
declare(strict_types=1);

namespace BlackCat\Crypto\CLI;

use BlackCat\Crypto\CLI\Command\CommandInterface;
use BlackCat\Crypto\CLI\Command\KeyGenerateCommand;
use BlackCat\Crypto\CLI\Command\WrapStatusCommand;
use BlackCat\Crypto\CLI\Command\KmsDiagCommand;
use BlackCat\Crypto\CLI\Command\WrapQueueCommand;
use BlackCat\Crypto\CLI\Command\MetricsExportCommand;
use BlackCat\Crypto\CLI\Command\TelemetrySseCommand;
use BlackCat\Crypto\CLI\Command\KmsWatchdogCommand;
use Psr\Log\NullLogger;

final class Application
{
    /** @var array<string,CommandInterface> */
    private array $commands = [];

    public function __construct()
    {
        $logger = new NullLogger();
        $this->register(new KeyGenerateCommand($logger));
        $this->register(new WrapStatusCommand());
        $this->register(new KmsDiagCommand($logger));
        $this->register(new WrapQueueCommand($logger));
        $this->register(new MetricsExportCommand($logger));
        $this->register(new TelemetrySseCommand($logger));
        $this->register(new KmsWatchdogCommand($logger));
    }

    public function register(CommandInterface $command): void
    {
        $this->commands[$command->name()] = $command;
    }

    public function run(array $argv): int
    {
        $command = $argv[1] ?? 'help';
        if ($command === 'help' || !isset($this->commands[$command])) {
            $this->printHelp();
            return $command === 'help' ? 0 : 1;
        }
        return $this->commands[$command]->run(array_slice($argv, 2));
    }

    private function printHelp(): void
    {
        echo "Available commands:\n";
        foreach ($this->commands as $command) {
            echo sprintf("  %s - %s\n", $command->name(), $command->description());
        }
    }
}

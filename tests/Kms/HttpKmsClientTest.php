<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Kms;

use BlackCat\Crypto\Kms\HttpKmsClient;
use BlackCat\Crypto\Support\Payload;
use PHPUnit\Framework\TestCase;

final class HttpKmsClientTest extends TestCase
{
    /** @var resource|null */
    private $process;
    private ?int $port = null;

    protected function tearDown(): void
    {
        parent::tearDown();
        $this->stopServer();
    }

    public function testWrapUnwrapAndHealth(): void
    {
        $port = $this->startServer();
        $client = new HttpKmsClient([
            'id' => 'fixture-kms',
            'endpoint' => "http://127.0.0.1:{$port}",
            'token' => 'test-token',
            'timeout' => 3,
        ]);
        $payload = new Payload('ciphertext', 'nonce', 'local-key');
        $metadata = $client->wrap('users.pii', $payload);
        self::assertArrayHasKey('ciphertext', $metadata);
        self::assertSame('fixture-kms', $metadata['client']);

        $roundTrip = $client->unwrap('users.pii', $metadata);
        self::assertSame($payload->ciphertext, $roundTrip->ciphertext);
        self::assertSame($payload->nonce, $roundTrip->nonce);

        $health = $client->health();
        self::assertSame('ok', $health['status']);
    }

    private function startServer(): int
    {
        if ($this->process) {
            return $this->port ?? 0;
        }
        $router = __DIR__ . '/../Fixtures/kms-router.php';
        $port = random_int(20050, 25050);
        $descriptor = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $cmd = sprintf('php -S 127.0.0.1:%d %s', $port, escapeshellarg($router));
        $this->process = proc_open($cmd, $descriptor, $pipes, dirname($router));
        if (!is_resource($this->process)) {
            self::fail('Unable to start HTTP test server');
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $deadline = microtime(true) + 5;
        $healthy = false;
        while (microtime(true) < $deadline) {
            $ctx = stream_context_create(['http' => ['timeout' => 0.2]]);
            $response = @file_get_contents("http://127.0.0.1:{$port}/healthz", false, $ctx);
            if ($response !== false) {
                $healthy = true;
                break;
            }
            usleep(100000);
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        if (!$healthy) {
            $this->stopServer();
            self::fail('KMS HTTP server did not start');
        }
        $this->port = $port;
        return $port;
    }

    private function stopServer(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
        $this->process = null;
        $this->port = null;
    }
}

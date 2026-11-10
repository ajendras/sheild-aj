<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use HookShield\Shield;
use HookShield\Router\EventRouter;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Runnable plain-PHP demo for Hook Shield.
 *
 * Run with: php -S localhost:8080 -t examples/plain-php
 *
 * This script loads (or falls back to) a configuration, registers an
 * EventRouter handler for UPI-style events (common with Indian payment
 * gateways), creates a PSR-7 request via Nyholm, and runs the full
 * protection pipeline.
 *
 * A log file (webhook.log) is written on successful event dispatch.
 */

$configFile = __DIR__ . '/config.php';
if (file_exists($configFile)) {
    $loaded = require $configFile;
    $config = is_array($loaded) ? $loaded : [];
} else {
    // Sensible defaults so the example runs as-is
    $config = [
        'secret' => 'test-secret-123',
        'validator' => 'hmac-sha256',
        'tolerance' => 300,
        'rate_limit' => [
            'max' => 100,
            'window' => 60,
        ],
    ];
}

// Ensure required services
if (!isset($config['cache']) || !$config['cache'] instanceof \Psr\Cache\CacheItemPoolInterface) {
    $config['cache'] = new ArrayAdapter();
}

$router = new EventRouter();

// Register handler for UPI events (demonstrates wildcard support "upi.*")
$router->register('upi.*', static function (string $event, array $payload): void {
    $logEntry = sprintf(
        "[%s] %s %s\n",
        date('Y-m-d H:i:s'),
        $event,
        json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)
    );
    file_put_contents(__DIR__ . '/webhook.log', $logEntry, FILE_APPEND | LOCK_EX);

    if (php_sapi_name() !== 'cli') {
        echo '✅ Event processed: ' . htmlspecialchars($event) . "\n";
    }
});

$config['router'] = $router;

// Create PSR-7 request from the current PHP globals (works with php -S)
$httpFactory = new Psr17Factory();
$creator = new ServerRequestCreator(
    $httpFactory, // ServerRequest
    $httpFactory, // Uri
    $httpFactory, // UploadedFile
    $httpFactory  // Stream
);

$request = $creator->fromGlobals();

$result = Shield::protect($request, $config);

header('Content-Type: application/json');

if ($result->isSuccessful()) {
    http_response_code(200);
    echo json_encode([
        'status' => 'success',
        'event' => $result->event,
        'message' => 'Webhook accepted and handlers executed.',
    ], JSON_PRETTY_PRINT);
} else {
    http_response_code(403);
    echo json_encode([
        'status' => 'error',
        'violations' => $result->violations,
    ], JSON_PRETTY_PRINT);
}

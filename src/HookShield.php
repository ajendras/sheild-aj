<?php

declare(strict_types=1);

namespace HookShield;

use GuzzleHttp\Psr7\ServerRequest;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use HookShield\Config\Configuration;
use HookShield\Protector\ReplayProtector;
use HookShield\RateLimiter;
use HookShield\Router\EventRouter;
use HookShield\Threat\ThreatDetector;
use HookShield\Validator\HmacSha256Validator;
use HookShield\Validator\RsaPssValidator;
use HookShield\Validator\SignatureValidator;
use HookShield\Validator\StripeValidator;
use HookShield\Validator\RazorpayValidator;

/**
 * Value object representing the outcome of webhook protection.
 */
final class Result
{
    /**
     * @param bool $success Whether all security checks passed
     * @param list<string> $violations Human-readable violation messages (empty on success)
     * @param string|null $event The extracted event name (if available)
     * @param array<string, mixed> $payload The decoded webhook payload
     */
    public function __construct(
        public readonly bool $success,
        public readonly array $violations = [],
        public readonly ?string $event = null,
        public readonly array $payload = [],
    ) {
    }

    /**
     * Whether the webhook passed validation and can be processed.
     */
    public function isSuccessful(): bool
    {
        return $this->success;
    }
}

/**
 * Main facade for Hook Shield.
 *
 * Provides a simple, secure API for protecting incoming webhooks and a test helper.
 */
final class Shield
{
    /**
     * Protects an incoming PSR-7 webhook request with signature validation,
     * replay protection, rate limiting and threat detection.
     *
     * @param ServerRequestInterface $request The incoming webhook request
     * @param array<string, mixed> $config Configuration (secret is required)
     * @return Result Protection result
     * @throws \InvalidArgumentException On missing required configuration
     */
    public static function protect(ServerRequestInterface $request, array $config = []): Result
    {
        $config = Configuration::validate($config);

        if (empty($config['secret'])) {
            throw new \InvalidArgumentException('Configuration must contain a non-empty "secret" key.');
        }

        $bodyStream = $request->getBody();
        $payload = $bodyStream->getContents();
        // Rewind for potential downstream use (middleware pattern)
        if ($bodyStream->isSeekable()) {
            $bodyStream->rewind();
        }

        $headers = $request->getHeaders();
        $meta = [
            'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? '0.0.0.0',
            'user_agent' => $headers['user-agent'][0] ?? '',
            'method' => $request->getMethod(),
            'content_length' => strlen($payload),
        ];

        $signature = self::extractSignature($headers, $config['signature'] ?? []);
        if ($signature === null || $signature === '') {
            return new Result(false, ['Missing or empty signature header'], null, []);
        }

        $validator = self::createValidator($config['validator'] ?? 'hmac-sha256');
        $signatureValid = $validator->validate($payload, $signature, $config['secret']);

        if (!$signatureValid) {
            self::logAttempt($config['logger'] ?? null, 'invalid_signature', $meta);
            return new Result(false, ['Invalid signature'], null, []);
        }

        $timestamp = self::extractTimestamp($headers);
        $nonce = self::extractNonce($headers);

        $cache = $config['cache'] ?? new ArrayAdapter();
        $replayProtector = new ReplayProtector($cache);

        if ($nonce !== '' && $replayProtector->isReplay($nonce, $timestamp, (int) $config['tolerance'])) {
            self::logAttempt($config['logger'] ?? null, 'replay_detected', $meta);
            return new Result(false, ['Replay detected'], null, []);
        }

        $rateLimiter = new RateLimiter($cache);
        $origin = $meta['ip'];
        $maxRequests = (int) ($config['rate_limit']['max'] ?? 100);
        $windowSeconds = (int) ($config['rate_limit']['window'] ?? 60);

        if (!$rateLimiter->limit($origin, $maxRequests, $windowSeconds)) {
            self::logAttempt($config['logger'] ?? null, 'rate_limited', $meta);
            return new Result(false, ['Rate limit exceeded'], null, []);
        }

        $parsedPayload = [];
        if ($payload !== '') {
            $parsedPayload = json_decode($payload, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $parsedPayload = [];
            }
        }

        $threatDetector = new ThreatDetector();
        // Default rules from config
        foreach ($config['rules'] ?? [] as $rule) {
            if (is_callable($rule)) {
                $threatDetector->addRule($rule);
            }
        }
        $violations = $threatDetector->detect($parsedPayload, $meta);

        if ($violations !== []) {
            self::logAttempt($config['logger'] ?? null, 'threat_detected', $meta, $violations);
            return new Result(false, $violations, null, $parsedPayload);
        }

        $event = self::extractEvent($headers, $parsedPayload);

        $router = $config['router'] ?? null;
        if ($router instanceof EventRouter) {
            $router->dispatch($event, $parsedPayload);
        }

        self::logAttempt($config['logger'] ?? null, 'success', $meta, [], $event);

        return new Result(true, [], $event, $parsedPayload);
    }

    /**
     * Convenience method for testing webhooks locally.
     *
     * Builds a synthetic PSR-7 request and runs it through protect().
     *
     * @param string $event Event name to simulate
     * @param array<string, mixed> $payload Event payload
     * @param string $secret HMAC secret
     * @return Result Test result
     */
    public static function test(string $event, array $payload, string $secret): Result
    {
        if ($secret === '') {
            throw new \InvalidArgumentException('Test secret cannot be empty.');
        }

        $payload['event'] = $event; // embed for extraction
        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        $signature = hash_hmac('sha256', $json, $secret);

        $request = new ServerRequest(
            'POST',
            'https://example.com/webhooks',
            [
                'Content-Type' => 'application/json',
                'X-Signature' => $signature,
                'X-Event' => $event,
                'X-Timestamp' => (string) time(),
                'X-Nonce' => bin2hex(random_bytes(16)),
            ],
            $json
        );

        $config = [
            'secret' => $secret,
            'validator' => 'hmac-sha256',
            'tolerance' => 300,
            'rate_limit' => ['max' => 100, 'window' => 60],
            'cache' => new ArrayAdapter(),
            'rules' => [],
        ];

        return self::protect($request, $config);
    }

    private static function extractSignature(array $headers, array $config): ?string
    {
        $headerName = strtolower($config['header'] ?? 'x-signature');
        $prefix = $config['prefix'] ?? '';

        foreach ($headers as $key => $values) {
            if (strtolower($key) === $headerName && isset($values[0])) {
                $value = (string) $values[0];
                if ($prefix !== '' && str_starts_with($value, $prefix)) {
                    return substr($value, strlen($prefix));
                }
                return $value;
            }
        }

        return null;
    }

    private static function extractTimestamp(array $headers): int
    {
        foreach ($headers as $key => $values) {
            $lowerKey = strtolower($key);
            if (in_array($lowerKey, ['x-timestamp', 't', 'x-webhook-timestamp'], true) && isset($values[0])) {
                return (int) $values[0];
            }

            if ($lowerKey === 'stripe-signature' && isset($values[0])) {
                $sig = (string) $values[0];
                if (preg_match('/t=(\d+)/', $sig, $matches)) {
                    return (int) $matches[1];
                }
            }
        }

        return time();
    }

    private static function extractNonce(array $headers): string
    {
        foreach (['x-nonce', 'x-request-id', 'x-webhook-id'] as $name) {
            if (isset($headers[$name][0])) {
                return (string) $headers[$name][0];
            }
        }
        return '';
    }

    private static function extractEvent(array $headers, array $payload): string
    {
        if (isset($payload['event']) && is_string($payload['event'])) {
            return $payload['event'];
        }
        foreach (['x-event', 'x-webhook-event'] as $name) {
            if (isset($headers[$name][0])) {
                return (string) $headers[$name][0];
            }
        }
        return 'webhook.unknown';
    }

    private static function createValidator(string $type): SignatureValidator
    {
        return match (strtolower($type)) {
            'hmac-sha256', 'hmac' => new HmacSha256Validator(),
            'rsa-pss', 'rsa' => new RsaPssValidator(),
            'stripe' => new StripeValidator(),
            'razorpay' => new RazorpayValidator(),
            default => throw new \InvalidArgumentException(sprintf('Unknown validator type "%s".', $type)),
        };
    }

    /**
     * Logs a webhook attempt using the configured PSR-3 logger (if present).
     * Sensitive data is redacted.
     */
    private static function logAttempt(
        ?LoggerInterface $logger,
        string $outcome,
        array $meta,
        array $violations = [],
        ?string $event = null
    ): void {
        if ($logger === null) {
            return;
        }

        $context = [
            'outcome' => $outcome,
            'ip' => $meta['ip'],
            'event' => $event,
        ];

        if ($violations !== []) {
            $context['violations'] = $violations;
        }

        $level = $outcome === 'success' ? 'info' : 'warning';
        $logger->log($level, 'Webhook processed', $context);
    }
}

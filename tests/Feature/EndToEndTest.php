<?php

declare(strict_types=1);

namespace HookShield\Tests\Feature;

use GuzzleHttp\Psr7\ServerRequest;
use HookShield\Result;
use HookShield\Shield;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Full end-to-end tests exercising the complete webhook protection pipeline.
 *
 * Verifies that:
 *  - A correctly signed webhook with fresh nonce passes all checks.
 *  - A replay (duplicate nonce) is rejected.
 *  - Rate limiting correctly blocks excess requests from the same origin.
 */
final class EndToEndTest extends TestCase
{
    public function testValidWebhookPassesAllChecks(): void
    {
        $cache = new ArrayAdapter();
        $secret = 'valid-webhook-secret-9876';
        $payload = [
            'event' => 'upi.payment.succeeded',
            'transaction_id' => 'txn_abc123',
            'amount' => 1500,
            'currency' => 'INR',
        ];
        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        $signature = hash_hmac('sha256', $json, $secret);
        $nonce = bin2hex(random_bytes(16));
        $timestamp = time();

        $request = new ServerRequest(
            'POST',
            'https://example.com/webhooks/upi',
            [
                'Content-Type' => 'application/json',
                'X-Signature' => $signature,
                'X-Timestamp' => (string) $timestamp,
                'X-Nonce' => $nonce,
                'X-Event' => 'upi.payment.succeeded',
            ],
            $json,
            '1.1',
            ['REMOTE_ADDR' => '192.0.2.1']
        );

        $config = [
            'secret' => $secret,
            'validator' => 'hmac-sha256',
            'tolerance' => 300,
            'cache' => $cache,
            'rate_limit' => ['max' => 10, 'window' => 60],
            'rules' => [],
        ];

        $result = Shield::protect($request, $config);

        $this->assertTrue($result->isSuccessful());
        $this->assertSame('upi.payment.succeeded', $result->event);
        $this->assertSame($payload, $result->payload);
        $this->assertSame([], $result->violations);
    }

    public function testReplayAttackIsBlocked(): void
    {
        $cache = new ArrayAdapter();
        $secret = 'replay-test-secret';
        $payload = ['event' => 'test.replay', 'id' => 42];
        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        $signature = hash_hmac('sha256', $json, $secret);
        $nonce = 'replay-nonce-' . bin2hex(random_bytes(8));
        $timestamp = time();

        $headers = [
            'Content-Type' => 'application/json',
            'X-Signature' => $signature,
            'X-Timestamp' => (string) $timestamp,
            'X-Nonce' => $nonce,
        ];

        $request = new ServerRequest(
            'POST',
            '/webhook',
            $headers,
            $json,
            '1.1',
            ['REMOTE_ADDR' => '10.0.0.1']
        );

        $config = [
            'secret' => $secret,
            'cache' => $cache,
            'tolerance' => 120,
            'rate_limit' => ['max' => 20, 'window' => 60],
        ];

        // First request should succeed
        $result1 = Shield::protect($request, $config);
        $this->assertTrue($result1->isSuccessful(), 'First request with unique nonce should pass');

        // Identical second request (same nonce) should be rejected as replay
        $result2 = Shield::protect($request, $config);
        $this->assertFalse($result2->isSuccessful());
        $this->assertContains('Replay detected', $result2->violations);
    }

    public function testRateLimitBlocksExcessRequests(): void
    {
        $cache = new ArrayAdapter();
        $secret = 'rate-limit-test-secret';
        $payload = ['event' => 'test.rate.limit', 'value' => 999];
        $json = json_encode($payload, JSON_THROW_ON_ERROR);
        $signature = hash_hmac('sha256', $json, $secret);
        $baseTimestamp = time();

        $config = [
            'secret' => $secret,
            'cache' => $cache,
            'tolerance' => 300,
            'rate_limit' => ['max' => 3, 'window' => 30],
            'rules' => [],
        ];

        $ip = '203.0.113.5';
        $successful = 0;
        $rateLimited = false;
        $violations = [];

        for ($i = 0; $i < 6; $i++) {
            $nonce = 'rate-' . $i . '-' . bin2hex(random_bytes(8));

            $request = new ServerRequest(
                'POST',
                '/webhooks',
                [
                    'Content-Type' => 'application/json',
                    'X-Signature' => $signature,
                    'X-Timestamp' => (string) ($baseTimestamp + $i),
                    'X-Nonce' => $nonce,
                ],
                $json,
                '1.1',
                ['REMOTE_ADDR' => $ip]
            );

            $result = Shield::protect($request, $config);

            if ($result->isSuccessful()) {
                $successful++;
            } else {
                $rateLimited = true;
                $violations = $result->violations;
                break;
            }
        }

        $this->assertGreaterThan(0, $successful);
        $this->assertLessThan(6, $successful, 'Some requests should have been rate limited');
        $this->assertTrue($rateLimited);
        $this->assertContains('Rate limit exceeded', $violations);
    }

    public function testThreatDetectionRejectsLargePayload(): void
    {
        $cache = new ArrayAdapter();
        $secret = 'threat-test-secret';
        $largePayload = ['event' => 'test.large', 'data' => str_repeat('x', 70000)];
        $json = json_encode($largePayload, JSON_THROW_ON_ERROR);
        $signature = hash_hmac('sha256', $json, $secret);

        $request = new ServerRequest(
            'POST',
            '/webhook',
            [
                'Content-Type' => 'application/json',
                'X-Signature' => $signature,
                'X-Timestamp' => (string) time(),
                'X-Nonce' => bin2hex(random_bytes(16)),
            ],
            $json,
            '1.1',
            ['REMOTE_ADDR' => '127.0.0.1']
        );

        $config = [
            'secret' => $secret,
            'cache' => $cache,
            'rules' => [
                \HookShield\Threat\ThreatDetector::payloadSizeRule(1024),
            ],
        ];

        $result = Shield::protect($request, $config);

        $this->assertFalse($result->isSuccessful());
        $this->assertStringContainsString('Payload size', $result->violations[0] ?? '');
    }

    public function testStripePresetSignatureIsAccepted(): void
    {
        $cache = new ArrayAdapter();
        $secret = 'whsec_test_1234567890abcdef';
        $payloadArr = [
            'event' => 'checkout.session.completed',
            'id' => 'cs_test_123',
            'amount_total' => 2500,
        ];
        $json = json_encode($payloadArr, JSON_THROW_ON_ERROR);

        $timestamp = time();
        $signedPayload = $timestamp . '.' . $json;
        $signature = hash_hmac('sha256', $signedPayload, $secret);
        $stripeSigHeader = "t={$timestamp},v1={$signature}";

        $nonce = bin2hex(random_bytes(16));

        $request = new ServerRequest(
            'POST',
            '/stripe/webhook',
            [
                'Content-Type' => 'application/json',
                'Stripe-Signature' => $stripeSigHeader,
                'X-Nonce' => $nonce,
            ],
            $json,
            '1.1',
            ['REMOTE_ADDR' => '3.1.2.3']
        );

        $config = [
            'secret' => $secret,
            'validator' => 'stripe',
            'signature' => ['header' => 'stripe-signature'],
            'cache' => $cache,
            'tolerance' => 300,
            'rate_limit' => ['max' => 10, 'window' => 60],
            'rules' => [],
        ];

        $result = Shield::protect($request, $config);

        $this->assertTrue($result->isSuccessful());
        $this->assertSame('checkout.session.completed', $result->event);
        $this->assertSame($payloadArr, $result->payload);
        $this->assertSame([], $result->violations);
    }

    public function testHeadersAreCaseInsensitiveForExtraction(): void
    {
        $cache = new ArrayAdapter();
        $secret = 'case-insensitive-test-secret';
        $json = '{"event":"test.case.insensitive","id":999}';
        $signature = hash_hmac('sha256', $json, $secret);
        $nonce = 'nonce-' . bin2hex(random_bytes(8));
        $timestamp = time();

        $request = new ServerRequest(
            'POST',
            '/webhook',
            [
                'content-type' => 'application/json',
                'x-signature' => $signature,
                'X-TIMESTAMP' => (string) $timestamp,
                'x-nonce' => $nonce,
                'X-EVENT' => 'test.case.insensitive',
            ],
            $json,
            '1.1',
            ['REMOTE_ADDR' => '192.0.2.1']
        );

        $config = [
            'secret' => $secret,
            'validator' => 'hmac-sha256',
            'cache' => $cache,
            'tolerance' => 300,
            'rate_limit' => ['max' => 5, 'window' => 60],
            'rules' => [],
        ];

        $result = Shield::protect($request, $config);

        $this->assertTrue($result->isSuccessful(), 'Should accept with mixed-case headers');
        $this->assertSame('test.case.insensitive', $result->event);
    }
}

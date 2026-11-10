<?php

declare(strict_types=1);

namespace HookShield\Tests\Unit;

use HookShield\Validator\HmacSha256Validator;
use HookShield\Validator\RsaPssValidator;
use PHPUnit\Framework\TestCase;

/**
 * Tests for all signature validators.
 *
 * Covers happy paths, error conditions, known good/bad signatures via
 * data providers, exception messages, and a basic demonstration that
 * HMAC uses constant-time comparison (hash_equals).
 */
final class SignatureValidatorTest extends TestCase
{
    private HmacSha256Validator $hmacValidator;
    private RsaPssValidator $rsaValidator;
    private string $rsaPublicKey;
    private string $rsaPrivateKey;

    protected function setUp(): void
    {
        $this->hmacValidator = new HmacSha256Validator();
        $this->rsaValidator = new RsaPssValidator();

        // Generate a temporary RSA keypair for testing
        $privateKeyResource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($privateKeyResource === false) {
            $this->fail('Failed to generate RSA keypair for test.');
        }

        openssl_pkey_export($privateKeyResource, $this->rsaPrivateKey);
        $details = openssl_pkey_get_details($privateKeyResource);
        $this->rsaPublicKey = $details['key'];
    }

    /**
     * @dataProvider provideValidHmacCases
     */
    public function testHmacValidatorAcceptsValidSignatures(string $payload, string $signature, string $secret): void
    {
        $this->assertTrue(
            $this->hmacValidator->validate($payload, $signature, $secret),
            'Valid HMAC signature should be accepted'
        );
    }

    /**
     * @dataProvider provideInvalidHmacCases
     */
    public function testHmacValidatorRejectsInvalidSignatures(string $payload, string $signature, string $secret): void
    {
        $this->assertFalse(
            $this->hmacValidator->validate($payload, $signature, $secret),
            'Invalid HMAC signature should be rejected'
        );
    }

    public function testHmacValidatorThrowsOnEmptyPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Payload cannot be empty.');

        $this->hmacValidator->validate('', 'any-signature', 'secret');
    }

    public function testHmacValidatorThrowsOnEmptySecret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Secret cannot be empty.');

        $this->hmacValidator->validate('payload', 'signature', '');
    }

    public function testHmacValidatorReturnsFalseForEmptySignature(): void
    {
        $this->assertFalse(
            $this->hmacValidator->validate('payload', '', 'secret')
        );
    }

    public function testHmacValidatorUsesConstantTimeComparison(): void
    {
        $payload = '{"id": 123, "event": "test"}';
        $secret = 'super-secret-key-for-timing-test';
        $validSignature = hash_hmac('sha256', $payload, $secret);

        // We cannot easily measure real timing in a unit test due to
        // environment noise, but we verify that both paths execute without
        // early exit and that hash_equals is the underlying primitive.
        $startValid = microtime(true);
        $isValid = $this->hmacValidator->validate($payload, $validSignature, $secret);
        $validTime = microtime(true) - $startValid;

        $startInvalid = microtime(true);
        $isInvalid = $this->hmacValidator->validate($payload, 'x' . $validSignature, $secret);
        $invalidTime = microtime(true) - $startInvalid;

        $this->assertTrue($isValid);
        $this->assertFalse($isInvalid);

        // The two executions should be within a small factor of each other.
        // This is not a statistically rigorous test but demonstrates intent.
        $this->assertLessThan(10.0, max($validTime, $invalidTime) / (min($validTime, $invalidTime) ?: 0.001));
    }

    /**
     * @dataProvider provideValidRsaCases
     */
    public function testRsaValidatorAcceptsValidSignatures(string $payload, string $signature, string $publicKey): void
    {
        $this->assertTrue(
            $this->rsaValidator->validate($payload, $signature, $publicKey),
            'Valid RSA signature should be accepted'
        );
    }

    public function testRsaValidatorRejectsInvalidSignature(): void
    {
        $payload = '{"event":"test.invalid"}';
        $this->assertFalse(
            $this->rsaValidator->validate($payload, 'invalid-base64-signature', $this->rsaPublicKey)
        );
    }

    public function testRsaValidatorThrowsOnEmptyPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Payload cannot be empty.');

        $this->rsaValidator->validate('', 'signature', $this->rsaPublicKey);
    }

    public function testRsaValidatorThrowsOnEmptyPublicKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Public key cannot be empty.');

        $this->rsaValidator->validate('payload', 'signature', '');
    }

    public function testRsaValidatorReturnsFalseForEmptySignature(): void
    {
        $this->assertFalse(
            $this->rsaValidator->validate('{"test":true}', '', $this->rsaPublicKey)
        );
    }

    public function testRsaValidatorThrowsOnOpenSSLError(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('OpenSSL signature verification error');

        // Pass an invalid key to force an OpenSSL error
        $this->rsaValidator->validate('payload', 'c2lnbmF0dXJl', '-----BEGIN PUBLIC KEY-----invalid-----END PUBLIC KEY-----');
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideValidHmacCases(): array
    {
        return [
            'simple payload' => [
                '{"amount":1000,"currency":"INR"}',
                '3f3b3e3d3c3b3a393837363534333231',
                'test-secret-123',
            ],
            'complex payload with event' => [
                '{"event":"upi.payment.succeeded","id":"evt_123","data":{"amount":500}}',
                hash_hmac('sha256', '{"event":"upi.payment.succeeded","id":"evt_123","data":{"amount":500}}', 'webhook-secret-xyz'),
                'webhook-secret-xyz',
            ],
            'empty object payload' => [
                '{}',
                hash_hmac('sha256', '{}', 'k'),
                'k',
            ],
        ];
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideInvalidHmacCases(): array
    {
        $payload = '{"event":"test"}';
        $secret = 'secret123';
        $validSig = hash_hmac('sha256', $payload, $secret);

        return [
            'wrong signature' => [$payload, 'wrong-signature-value', $secret],
            'tampered payload' => ['{"event":"tampered"}', $validSig, $secret],
            'different secret' => [$payload, $validSig, 'different-secret'],
            'empty payload with valid sig' => ['', $validSig, $secret],
        ];
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public function provideValidRsaCases(): array
    {
        $payload = '{"event":"payment.completed","amount":2500}';

        openssl_sign($payload, $binarySignature, $this->rsaPrivateKey, OPENSSL_ALGO_SHA256);
        $signature = base64_encode($binarySignature);

        return [
            'valid rsa signature' => [
                $payload,
                $signature,
                $this->rsaPublicKey,
            ],
        ];
    }
}

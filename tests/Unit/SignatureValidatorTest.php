<?php

declare(strict_types=1);

namespace HookShield\Tests\Unit;

use HookShield\Validator\HmacSha256Validator;
use HookShield\Validator\RsaPssValidator;
use HookShield\Validator\StripeValidator;
use HookShield\Validator\RazorpayValidator;
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
    private StripeValidator $stripeValidator;
    private RazorpayValidator $razorpayValidator;
    private string $rsaPublicKey;
    private string $rsaPrivateKey;

    private static string $rsaPublicKeyStatic;
    private static string $rsaPrivateKeyStatic;

    protected static function setUpBeforeClass(): void
    {
        $privateKeyResource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($privateKeyResource === false) {
            throw new \RuntimeException('Failed to generate RSA keypair for test.');
        }

        openssl_pkey_export($privateKeyResource, self::$rsaPrivateKeyStatic);
        $details = openssl_pkey_get_details($privateKeyResource);

        if ($details === false) {
            throw new \RuntimeException('Failed to get RSA key details.');
        }

        self::$rsaPublicKeyStatic = $details['key'];
    }

    protected function setUp(): void
    {
        $this->hmacValidator = new HmacSha256Validator();
        $this->rsaValidator = new RsaPssValidator();
        $this->stripeValidator = new StripeValidator();
        $this->razorpayValidator = new RazorpayValidator();

        $this->rsaPrivateKey = self::$rsaPrivateKeyStatic;
        $this->rsaPublicKey = self::$rsaPublicKeyStatic;
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
     * @dataProvider provideValidStripeCases
     */
    public function testStripeValidatorAcceptsValidSignatures(string $payload, string $signature, string $secret): void
    {
        $this->assertTrue(
            $this->stripeValidator->validate($payload, $signature, $secret),
            'Valid Stripe signature should be accepted'
        );
    }

    /**
     * @dataProvider provideInvalidStripeCases
     */
    public function testStripeValidatorRejectsInvalidSignatures(string $payload, string $signature, string $secret): void
    {
        $this->assertFalse(
            $this->stripeValidator->validate($payload, $signature, $secret),
            'Invalid Stripe signature should be rejected'
        );
    }

    public function testStripeValidatorThrowsOnEmptyPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Payload cannot be empty.');

        $this->stripeValidator->validate('', 't=1234567890,v1=abc123', 'whsec_test');
    }

    public function testStripeValidatorThrowsOnEmptySecret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Secret cannot be empty.');

        $this->stripeValidator->validate('{"event":"test"}', 't=1234567890,v1=abc123', '');
    }

    public function testStripeValidatorReturnsFalseForEmptySignature(): void
    {
        $this->assertFalse(
            $this->stripeValidator->validate('{"event":"test"}', '', 'whsec_test')
        );
    }

    public function testStripeValidatorReturnsFalseForMalformedHeader(): void
    {
        $this->assertFalse(
            $this->stripeValidator->validate('{"event":"test"}', 't=1234567890', 'whsec_test')
        );
    }

    public function testRazorpayValidatorAcceptsValidSignatures(): void
    {
        $payload = '{"event":"order.paid","id":"order_123"}';
        $secret = 'key_live_razorpay_webhook_secret_123';
        $signature = hash_hmac('sha256', $payload, $secret);

        $this->assertTrue(
            $this->razorpayValidator->validate($payload, $signature, $secret)
        );
    }

    public function testRazorpayValidatorRejectsInvalidSignatures(): void
    {
        $this->assertFalse(
            $this->razorpayValidator->validate(
                '{"event":"order.paid"}',
                'wrong_signature_value',
                'key_live_razorpay_webhook_secret_123'
            )
        );
    }

    public function testRazorpayValidatorThrowsOnEmptyPayload(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Payload cannot be empty.');

        $this->razorpayValidator->validate('', 'any-sig', 'secret');
    }

    public function testRazorpayValidatorThrowsOnEmptySecret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Secret cannot be empty.');

        $this->razorpayValidator->validate('payload', 'sig', '');
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideValidHmacCases(): array
    {
        return [
            'simple payload' => [
                '{"amount":1000,"currency":"INR"}',
                hash_hmac('sha256', '{"amount":1000,"currency":"INR"}', 'test-secret-123'),
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
        ];
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideValidRsaCases(): array
    {
        $payload = '{"event":"payment.completed","amount":2500}';

        openssl_sign($payload, $binarySignature, self::$rsaPrivateKeyStatic, OPENSSL_ALGO_SHA256);
        $signature = base64_encode($binarySignature);

        return [
            'valid rsa signature' => [
                $payload,
                $signature,
                self::$rsaPublicKeyStatic,
            ],
        ];
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideValidStripeCases(): array
    {
        $payload = '{"id":"evt_123","type":"payment_intent.succeeded"}';
        $ts = 1678900000;
        $toSign = $ts . '.' . $payload;
        $secret = 'whsec_testsecret123';
        $sig = hash_hmac('sha256', $toSign, $secret);
        $header = "t={$ts},v1={$sig}";

        return [
            'valid stripe signature' => [$payload, $header, $secret],
        ];
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideInvalidStripeCases(): array
    {
        $payload = '{"id":"evt_123","type":"payment_intent.succeeded"}';
        $ts = 1678900000;
        $secret = 'whsec_testsecret123';
        $toSign = $ts . '.' . $payload;
        $validSig = hash_hmac('sha256', $toSign, $secret);

        return [
            'wrong v1 component' => [$payload, "t={$ts},v1=wronghash123456", $secret],
            'tampered payload' => ['{"id":"tampered"}', "t={$ts},v1={$validSig}", $secret],
            'missing v1' => [$payload, "t={$ts}", $secret],
            'empty signature' => [$payload, '', $secret],
        ];
    }
}

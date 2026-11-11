<?php

declare(strict_types=1);

namespace HookShield\Validator;

/**
 * Interface for pluggable signature validators.
 *
 * All implementations must use constant-time comparison to mitigate
 * timing attacks. The library ships with validators for HMAC-SHA256,
 * RSA-PSS and dedicated presets for Stripe and Razorpay.
 */
interface SignatureValidator
{
    /**
     * Validate payload signature.
     *
     * @param string $payload Raw request body (never empty)
     * @param string $signature Signature value extracted from headers
     * @param string $secret Secret key (HMAC) or public key (RSA)
     * @return bool True if signature matches
     * @throws \InvalidArgumentException When arguments are invalid
     */
    public function validate(string $payload, string $signature, string $secret): bool;
}

/**
 * Validates HMAC-SHA256 signatures using constant-time hash_equals().
 *
 * Used by Stripe, GitHub, Shopify and most UPI/payment gateways.
 */
final class HmacSha256Validator implements SignatureValidator
{
    public function validate(string $payload, string $signature, string $secret): bool
    {
        if ($payload === '') {
            throw new \InvalidArgumentException('Payload cannot be empty.');
        }

        if ($secret === '') {
            throw new \InvalidArgumentException('Secret cannot be empty.');
        }

        if ($signature === '') {
            return false;
        }

        $computed = hash_hmac('sha256', $payload, $secret);

        return hash_equals($computed, $signature);
    }
}

/**
 * Validates RSA-PSS / RSA signatures via OpenSSL.
 *
 * The $secret argument is expected to be a PEM formatted public key.
 * Signature is assumed to be base64-encoded (common in SaaS webhooks).
 */
final class RsaPssValidator implements SignatureValidator
{
    public function validate(string $payload, string $signature, string $publicKey): bool
    {
        if ($payload === '') {
            throw new \InvalidArgumentException('Payload cannot be empty.');
        }

        if ($publicKey === '') {
            throw new \InvalidArgumentException('Public key cannot be empty.');
        }

        if ($signature === '') {
            return false;
        }

        $binarySig = base64_decode($signature, true);
        if ($binarySig === false) {
            $binarySig = $signature;
        }

        $result = openssl_verify($payload, $binarySig, $publicKey, OPENSSL_ALGO_SHA256);

        if ($result === -1) {
            $error = openssl_error_string() ?: 'Unknown OpenSSL error';
            throw new \RuntimeException('OpenSSL signature verification error: ' . $error);
        }

        return $result === 1;
    }
}

/**
 * Validates Stripe webhook signatures.
 *
 * Expects the full "stripe-signature" header value (e.g. "t=1678900000,v1=...").
 * Computes HMAC-SHA256 of "t={timestamp}.{payload}" and compares the v1 component
 * using constant-time hash_equals(). The embedded timestamp is extracted by
 * Shield::protect() for replay protection.
 */
final class StripeValidator implements SignatureValidator
{
    public function validate(string $payload, string $signature, string $secret): bool
    {
        if ($payload === '') {
            throw new \InvalidArgumentException('Payload cannot be empty.');
        }

        if ($secret === '') {
            throw new \InvalidArgumentException('Secret cannot be empty.');
        }

        if ($signature === '' || !str_contains($signature, 'v1=')) {
            return false;
        }

        // Parse t= and v1= components (Stripe format)
        $parts = [];
        $items = explode(',', $signature);
        foreach ($items as $item) {
            $item = trim($item);
            if (str_contains($item, '=')) {
                [$key, $value] = explode('=', $item, 2);
                $parts[trim($key)] = trim($value);
            }
        }

        if (!isset($parts['v1']) || !isset($parts['t'])) {
            return false;
        }

        $signedPayload = $parts['t'] . '.' . $payload;
        $computed = hash_hmac('sha256', $signedPayload, $secret);

        return hash_equals($computed, $parts['v1']);
    }
}

/**
 * Validates Razorpay webhook signatures using HMAC-SHA256.
 *
 * Razorpay sends a standard HMAC-SHA256 hash of the raw payload in the
 * X-Razorpay-Signature header. This preset uses the same constant-time
 * verification as the generic HMAC validator.
 */
final class RazorpayValidator implements SignatureValidator
{
    public function validate(string $payload, string $signature, string $secret): bool
    {
        if ($payload === '') {
            throw new \InvalidArgumentException('Payload cannot be empty.');
        }

        if ($secret === '') {
            throw new \InvalidArgumentException('Secret cannot be empty.');
        }

        if ($signature === '') {
            return false;
        }

        $computed = hash_hmac('sha256', $payload, $secret);

        return hash_equals($computed, $signature);
    }
}

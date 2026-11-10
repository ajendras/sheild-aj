<?php

declare(strict_types=1);

namespace HookShield\Validator;

/**
 * Interface for pluggable signature validators.
 *
 * All implementations must use constant-time comparison to mitigate
 * timing attacks.
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

<?php

declare(strict_types=1);

namespace HookShield\Threat;

/**
 * Threat detector that runs configurable rules against webhook payloads and metadata.
 *
 * Rules are simple callables that receive ($payload, $meta) and return a violation
 * string on failure or null/empty on success. Common rules for payload size, IP
 * blocklisting and basic schema validation are provided as static factories.
 */
final class ThreatDetector
{
    /**
     * @var list<callable(array<string, mixed>, array<string, mixed>): (string|null)>
     */
    private array $rules = [];

    /**
     * Add a custom threat detection rule.
     *
     * The rule callable receives the parsed payload and request metadata.
     * Return a non-empty string to signal a violation; return null or empty
     * string to pass.
     *
     * @param callable(array<string, mixed>, array<string, mixed>): (string|null) $rule
     * @return self For fluent chaining
     */
    public function addRule(callable $rule): self
    {
        $this->rules[] = $rule;

        return $this;
    }

    /**
     * Run all registered rules and return collected violation messages.
     *
     * @param array<string, mixed> $payload Parsed JSON payload
     * @param array<string, mixed> $meta Request metadata (ip, user_agent, content_length, ...)
     * @return list<string> List of violation messages (empty when no threats detected)
     */
    public function detect(array $payload, array $meta): array
    {
        $violations = [];

        foreach ($this->rules as $rule) {
            $violation = $rule($payload, $meta);

            if (is_string($violation) && $violation !== '') {
                $violations[] = $violation;
            }
        }

        return $violations;
    }

    /**
     * Adds a set of sensible default rules (payload size, IP blocklist stub).
     *
     * @return self For fluent chaining
     */
    public function addDefaultRules(): self
    {
        $this->addRule(self::payloadSizeRule(65536));
        $this->addRule(self::ipBlocklistRule([])); // empty list = no blocking by default

        return $this;
    }

    /**
     * Creates a rule that rejects payloads exceeding a byte limit.
     *
     * @param int $maxBytes Maximum allowed payload size in bytes
     * @return callable(array<string, mixed>, array<string, mixed>): (string|null)
     */
    public static function payloadSizeRule(int $maxBytes = 65536): callable
    {
        if ($maxBytes < 1024) {
            throw new \InvalidArgumentException('Maximum payload size must be at least 1024 bytes.');
        }

        return static function (array $payload, array $meta) use ($maxBytes): ?string {
            $size = (int) ($meta['content_length'] ?? 0);
            if ($size > $maxBytes) {
                return sprintf('Payload size %d bytes exceeds configured limit of %d bytes.', $size, $maxBytes);
            }

            return null;
        };
    }

    /**
     * Creates a rule that blocks requests from a list of IP addresses.
     *
     * @param list<string> $blockedIps List of IPs to block
     * @return callable(array<string, mixed>, array<string, mixed>): (string|null)
     */
    public static function ipBlocklistRule(array $blockedIps): callable
    {
        $blocked = array_map('strtolower', array_map('trim', $blockedIps));

        return static function (array $payload, array $meta) use ($blocked): ?string {
            $ip = (string) ($meta['ip'] ?? '');
            if ($ip === '') {
                return null;
            }

            if (in_array(strtolower(trim($ip)), $blocked, true)) {
                return sprintf('Request from blocked IP address: %s', $ip);
            }

            return null;
        };
    }

    /**
     * Creates a rule that requires specific keys to be present in the payload.
     *
     * @param list<string> $requiredKeys Keys that must exist and be non-empty
     * @return callable(array<string, mixed>, array<string, mixed>): (string|null)
     */
    public static function requiredFieldsRule(array $requiredKeys): callable
    {
        return static function (array $payload, array $meta) use ($requiredKeys): ?string {
            foreach ($requiredKeys as $key) {
                if (!isset($payload[$key]) || $payload[$key] === '' || $payload[$key] === null) {
                    return sprintf('Missing or empty required field: %s', $key);
                }
            }

            return null;
        };
    }
}

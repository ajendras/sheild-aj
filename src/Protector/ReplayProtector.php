<?php

declare(strict_types=1);

namespace HookShield\Protector;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Protects against replay attacks using timestamp validation and
 * nonce uniqueness checks backed by a PSR-6 cache.
 *
 * Uses constant-time operations where applicable and stores nonces
 * with a TTL based on tolerance to prevent replay within the window.
 */
final class ReplayProtector
{
    private CacheItemPoolInterface $cache;

    public function __construct(CacheItemPoolInterface $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Determines whether the provided nonce and timestamp represent a replay.
     *
     * A replay is detected if:
     * - The timestamp is outside the allowed tolerance window, OR
     * - The nonce has already been seen (cache hit).
     *
     * On first valid sighting the nonce is stored in cache.
     *
     * @param string $nonce Unique nonce from the webhook
     * @param int $ts Unix timestamp extracted from the webhook
     * @param int $tolerance Allowed clock skew in seconds (recommended >= 60)
     * @return bool True if this is a replay (should be rejected)
     * @throws \InvalidArgumentException On invalid input
     */
    public function isReplay(string $nonce, int $ts, int $tolerance): bool
    {
        if ($nonce === '') {
            throw new \InvalidArgumentException('Nonce must be a non-empty string.');
        }

        if ($tolerance < 30) {
            throw new \InvalidArgumentException('Tolerance must be at least 30 seconds for replay protection.');
        }

        if ($ts <= 0) {
            throw new \InvalidArgumentException('Timestamp must be a valid positive unix timestamp.');
        }

        $now = time();

        // Timestamp check first - prevents old or far-future replays
        if (abs($now - $ts) > $tolerance) {
            return true;
        }

        $key = 'hookshield:replay:' . hash('sha256', $nonce);

        $item = $this->cache->getItem($key);

        if ($item->isHit()) {
            return true;
        }

        $item->set(true);
        // Store slightly longer than tolerance to handle clock skew on both sides
        $item->expiresAfter(($tolerance * 2) + 30);

        $this->cache->save($item);

        return false;
    }
}

<?php

declare(strict_types=1);

namespace HookShield;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Sliding-window rate limiter using a PSR-6 cache backend.
 *
 * Stores a list of request timestamps per origin. On each check,
 * timestamps older than the window are pruned before evaluating
 * the limit. This provides an accurate sliding window without
 * fixed buckets.
 */
final class RateLimiter
{
    private CacheItemPoolInterface $cache;

    public function __construct(CacheItemPoolInterface $cache)
    {
        $this->cache = $cache;
    }

    /**
     * Checks and enforces rate limit for an origin using sliding window.
     *
     * @param string $origin Identifier for the rate limit subject (usually IP or vendor)
     * @param int $max Maximum number of requests allowed in the window
     * @param int $seconds Length of the sliding window in seconds
     * @return bool True if the request is within limits (allowed), false if exceeded
     * @throws \InvalidArgumentException When parameters are invalid
     */
    public function limit(string $origin, int $max, int $seconds): bool
    {
        if ($origin === '') {
            throw new \InvalidArgumentException('Origin identifier cannot be empty.');
        }

        if ($max < 1) {
            throw new \InvalidArgumentException('Maximum requests must be greater than zero.');
        }

        if ($seconds < 1) {
            throw new \InvalidArgumentException('Window size in seconds must be greater than zero.');
        }

        $key = 'hookshield:rate:' . hash('sha256', $origin);

        $item = $this->cache->getItem($key);

        $now = time();
        $windowStart = $now - $seconds;

        /** @var list<int> $requests */
        $requests = $item->isHit() && is_array($item->get()) ? $item->get() : [];

        // Prune timestamps outside the current sliding window
        $requests = array_values(array_filter(
            $requests,
            static fn(int $ts): bool => $ts >= $windowStart
        ));

        if (count($requests) >= $max) {
            return false;
        }

        $requests[] = $now;

        $item->set($requests);
        // Keep data a little longer than the window for safety
        $item->expiresAfter($seconds + 60);

        $this->cache->save($item);

        return true;
    }
}

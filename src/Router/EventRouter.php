<?php

declare(strict_types=1);

namespace HookShield\Router;

/**
 * Event router for dispatching validated webhooks to registered handlers.
 *
 * Supports exact event name matching and simple wildcard patterns (e.g. "upi.*",
 * "payment.*" or "*"). Handlers are stored in a priority queue (higher priority
 * executed first) and invoked with the event name and payload.
 *
 * Compatible with plain callables, closures, and Laravel/Symfony-style
 * array callables ([object, 'method']).
 */
final class EventRouter
{
    /**
     * @var array<string, array<int, list<callable|array>>>
     * Registered listeners: event-pattern => priority => list of handlers
     */
    private array $listeners = [];

    /**
     * Register a handler for an event name or pattern.
     *
     * @param string $eventName Event name or pattern. "*" or "prefix.*" supported.
     * @param callable|array $handler Handler to invoke on dispatch. Must be callable.
     * @param int $priority Higher numbers are executed earlier (default: 0)
     * @return self For fluent chaining
     * @throws \InvalidArgumentException On invalid event name or non-callable handler
     */
    public function register(string $eventName, callable|array $handler, int $priority = 0): self
    {
        if ($eventName === '') {
            throw new \InvalidArgumentException('Event name/pattern cannot be empty.');
        }

        if (!is_callable($handler)) {
            throw new \InvalidArgumentException(
                'Handler must be callable (closure, function, or array callable).'
            );
        }

        if (!isset($this->listeners[$eventName])) {
            $this->listeners[$eventName] = [];
        }

        if (!isset($this->listeners[$eventName][$priority])) {
            $this->listeners[$eventName][$priority] = [];
        }

        $this->listeners[$eventName][$priority][] = $handler;

        return $this;
    }

    /**
     * Dispatch an event to all matching registered handlers.
     *
     * Handlers are executed in descending priority order. Exceptions thrown
     * by a handler are not caught (fail-fast behavior).
     *
     * @param string $event The event identifier (e.g. "upi.payment.succeeded")
     * @param array<string, mixed> $payload The parsed webhook payload
     */
    public function dispatch(string $event, array $payload): void
    {
        if ($event === '') {
            return;
        }

        $candidates = $this->collectMatchingHandlers($event);

        if ($candidates === []) {
            return;
        }

        // Sort by priority descending (higher priority first)
        usort($candidates, static fn(array $a, array $b): int => $b[0] <=> $a[0]);

        foreach ($candidates as [, $handler]) {
            $handler($event, $payload);
        }
    }

    /**
     * Collect all handlers that match the dispatched event across all patterns.
     *
     * @return list<array{0: int, 1: callable|array}>
     */
    private function collectMatchingHandlers(string $event): array
    {
        $candidates = [];

        foreach ($this->listeners as $pattern => $priorityGroups) {
            if (!$this->matches($pattern, $event)) {
                continue;
            }

            foreach ($priorityGroups as $priority => $handlers) {
                foreach ($handlers as $handler) {
                    $candidates[] = [$priority, $handler];
                }
            }
        }

        return $candidates;
    }

    /**
     * Test whether a dispatched event matches a registered pattern.
     *
     * Supports:
     * - Exact match
     * - Wildcard "*" (matches everything)
     * - Suffix wildcard "prefix.*"
     */
    private function matches(string $pattern, string $event): bool
    {
        if ($pattern === $event || $pattern === '*') {
            return true;
        }

        if (str_ends_with($pattern, '.*')) {
            $prefix = substr($pattern, 0, -2);
            return $prefix !== '' && str_starts_with($event, $prefix);
        }

        return false;
    }

    /**
     * Returns all currently registered event patterns.
     *
     * Useful for introspection and testing.
     *
     * @return list<string>
     */
    public function getRegisteredPatterns(): array
    {
        return array_keys($this->listeners);
    }
}

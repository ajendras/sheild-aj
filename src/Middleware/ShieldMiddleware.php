<?php

declare(strict_types=1);

namespace HookShield\Middleware;

use HookShield\Result;
use HookShield\Shield;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use GuzzleHttp\Psr7\Response;

/**
 * PSR-15 middleware that protects webhook endpoints with the full Hook Shield suite.
 *
 * On failure it returns a 403 response with JSON error details. On success the
 * original request is augmented with a "hookshield.result" attribute containing
 * the Result value object before passing control to the next handler.
 */
final class ShieldMiddleware implements MiddlewareInterface
{
    /**
     * @param array<string, mixed> $config Configuration passed to Shield::protect().
     *                                    Must contain a valid 'secret' key.
     */
    public function __construct(
        private readonly array $config = []
    ) {
        if (!isset($this->config['secret']) || (string) $this->config['secret'] === '') {
            throw new \InvalidArgumentException('Middleware configuration must contain a non-empty "secret" key.');
        }
    }

    /**
     * Process an incoming server request and return a response.
     *
     * Runs the complete protection pipeline (signature, replay, rate limit,
     * threat detection). Returns 403 on any failure.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $result = Shield::protect($request, $this->config);

        if (!$result->isSuccessful()) {
            return $this->createFailureResponse($result);
        }

        // Attach result for downstream handlers/controllers
        $request = $request->withAttribute('hookshield.result', $result);

        if ($result->event !== null) {
            $request = $request->withAttribute('hookshield.event', $result->event);
        }

        if ($result->payload !== []) {
            $request = $request->withAttribute('hookshield.payload', $result->payload);
        }

        return $handler->handle($request);
    }

    /**
     * Creates a standardized JSON error response for failed webhook checks.
     */
    private function createFailureResponse(Result $result): ResponseInterface
    {
        $firstViolation = $result->violations[0] ?? 'Webhook security check failed';

        $body = [
            'error' => 'Webhook rejected',
            'message' => $firstViolation,
            'violations' => $result->violations,
        ];

        $json = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return new Response(
            403,
            [
                'Content-Type' => 'application/json',
                'X-Webhook-Status' => 'rejected',
            ],
            $json
        );
    }
}

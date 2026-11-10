<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use HookShield\Middleware\ShieldMiddleware;
use HookShield\Result;
use HookShield\Router\EventRouter;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Example Laravel controller demonstrating integration with Hook Shield.
 *
 * The route should be protected by ShieldMiddleware (or a Laravel wrapper
 * around it). The EventRouter is injected so handlers can be registered
 * in the constructor. The middleware enriches the request with a
 * "hookshield.result" attribute on success.
 *
 * Example route registration (routes/api.php):
 *
 * Route::post('/webhooks', [WebhookController::class, 'handle'])
 *     ->middleware(ShieldMiddleware::class);
 *
 * (In production, register the middleware with a config array containing
 * your secret, cache driver, etc. via a custom Laravel middleware or
 * service provider.)
 */
final class WebhookController extends Controller
{
    public function __construct(private readonly EventRouter $router)
    {
        $this->registerHandlers();
    }

    private function registerHandlers(): void
    {
        // Higher priority handlers run first
        $this->router->register('upi.*', [$this, 'handleUpiEvent'], 100);
        $this->router->register('payment.*', [$this, 'handlePaymentEvent'], 50);
        $this->router->register('*', [$this, 'handleFallbackEvent'], -100);
    }

    /**
     * Main webhook endpoint.
     *
     * ShieldMiddleware has already validated signature, replay, rate limits
     * and threats. We only need to handle the business outcome.
     */
    public function handle(Request $request): JsonResponse
    {
        /** @var Result|null $result */
        $result = $request->attributes->get('hookshield.result');

        if ($result === null || !$result->isSuccessful()) {
            return response()->json([
                'error' => 'Webhook rejected',
                'violations' => $result?->violations ?? ['Unknown validation failure'],
            ], 403);
        }

        return response()->json([
            'status' => 'success',
            'event' => $result->event,
            'message' => 'Webhook processed',
        ]);
    }

    /**
     * Handler for UPI events (common with Indian payment gateways).
     */
    public function handleUpiEvent(string $event, array $payload): void
    {
        // Replace with real business logic (e.g. update order, notify user, etc.)
        logger()->info('UPI webhook processed', [
            'event' => $event,
            'transaction_id' => $payload['transaction_id'] ?? null,
            'amount' => $payload['amount'] ?? null,
        ]);

        // Example: dispatch a job
        // ProcessUpiPayment::dispatch($payload);
    }

    /**
     * Handler for generic payment events.
     */
    public function handlePaymentEvent(string $event, array $payload): void
    {
        logger()->info('Payment webhook processed', [
            'event' => $event,
            'payload_keys' => array_keys($payload),
        ]);
    }

    /**
     * Catch-all fallback handler.
     */
    public function handleFallbackEvent(string $event, array $payload): void
    {
        logger()->warning('Unhandled webhook event received', [
            'event' => $event,
        ]);
    }
}

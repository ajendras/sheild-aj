<?php

declare(strict_types=1);

namespace HookShield\CLI;

use HookShield\Result;
use HookShield\Shield;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Symfony Console command to simulate webhook delivery for local testing.
 *
 * Supports both legitimate and malicious simulation via the --malicious flag.
 * Uses Shield::test() for legitimate cases and manually constructs a bad
 * signature for malicious test cases.
 */
final class TestCommand extends Command
{
    protected static $defaultName = 'test';
    protected static $defaultDescription = 'Simulate a webhook (legitimate or malicious) and run it through the protection pipeline';

    protected function configure(): void
    {
        $this
            ->setDescription(self::$defaultDescription)
            ->addOption('event', 'e', InputOption::VALUE_REQUIRED, 'Event name (e.g. upi.payment.succeeded)', 'payment.succeeded')
            ->addOption('payload', 'p', InputOption::VALUE_REQUIRED, 'JSON payload (use single quotes on CLI)', '{"amount": 1000, "currency": "INR"}')
            ->addOption('secret', 's', InputOption::VALUE_REQUIRED, 'HMAC secret key', 'test-secret-123')
            ->addOption('malicious', 'm', InputOption::VALUE_NONE, 'Simulate a malicious webhook (invalid signature)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        /** @var string $event */
        $event = $input->getOption('event');
        /** @var string $payloadJson */
        $payloadJson = $input->getOption('payload');
        /** @var string $secret */
        $secret = $input->getOption('secret');
        $malicious = (bool) $input->getOption('malicious');

        if ($event === '') {
            $io->error('Event name cannot be empty.');

            return Command::INVALID;
        }

        if ($secret === '') {
            $io->error('Secret cannot be empty.');

            return Command::INVALID;
        }

        $payload = [];
        if ($payloadJson !== '') {
            $decoded = json_decode($payloadJson, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $io->error('Invalid JSON in --payload option: ' . json_last_error_msg());

                return Command::INVALID;
            }
            $payload = is_array($decoded) ? $decoded : [];
        }

        $io->title('Hook Shield Test');
        $io->text(sprintf('Event: <info>%s</info>', $event));
        $io->text(sprintf('Secret: <info>%s</info>', str_repeat('*', min(8, strlen($secret)))));
        $io->text(sprintf('Mode: <info>%s</info>', $malicious ? 'MALICIOUS (invalid signature)' : 'LEGITIMATE'));
        $io->newLine();

        if ($malicious) {
            $result = $this->runMaliciousTest($event, $payload, $secret);
        } else {
            $result = Shield::test($event, $payload, $secret);
        }

        $this->renderResult($result, $io);

        return $result->isSuccessful() ? Command::SUCCESS : Command::FAILURE;
    }

    private function runMaliciousTest(string $event, array $payload, string $secret): Result
    {
        $payload['event'] = $event;
        $json = json_encode($payload, JSON_THROW_ON_ERROR);

        // Deliberately wrong signature
        $badSignature = 'invalid_signature_' . bin2hex(random_bytes(8));

        $request = new \GuzzleHttp\Psr7\ServerRequest(
            'POST',
            'https://example.com/webhooks',
            [
                'Content-Type' => 'application/json',
                'X-Signature' => $badSignature,
                'X-Event' => $event,
                'X-Timestamp' => (string) time(),
                'X-Nonce' => bin2hex(random_bytes(16)),
            ],
            $json
        );

        $config = [
            'secret' => $secret,
            'validator' => 'hmac-sha256',
            'tolerance' => 300,
            'rate_limit' => ['max' => 100, 'window' => 60],
            'cache' => new \Symfony\Component\Cache\Adapter\ArrayAdapter(),
            'rules' => [],
        ];

        return Shield::protect($request, $config);
    }

    private function renderResult(Result $result, SymfonyStyle $io): void
    {
        if ($result->isSuccessful()) {
            $io->success('WEBHOOK ACCEPTED');
            $io->definitionList(
                ['Event' => $result->event ?? 'unknown'],
                ['Payload keys' => implode(', ', array_keys($result->payload))],
            );

            return;
        }

        $io->error('WEBHOOK REJECTED');
        $io->listing($result->violations);

        if ($result->event !== null) {
            $io->text(sprintf('Detected event: <comment>%s</comment>', $result->event));
        }
    }
}

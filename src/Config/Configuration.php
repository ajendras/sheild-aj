<?php

declare(strict_types=1);

namespace HookShield\Config;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use HookShield\Router\EventRouter;

/**
 * Configuration loader and validator for Hook Shield.
 *
 * Provides defaults for all security parameters and performs strict
 * validation with clear error messages. Supports loading configuration
 * from PHP files that return an array.
 */
final class Configuration
{
    /**
     * Loads configuration from a PHP file that must return an array.
     *
     * The file is expected to return a partial configuration; defaults
     * will be merged and the result will be validated.
     *
     * @param string $path Absolute or relative path to the config file
     * @return array<string, mixed> Validated and normalized configuration
     * @throws \InvalidArgumentException If the file is missing or invalid
     */
    public static function load(string $path): array
    {
        if ($path === '') {
            throw new \InvalidArgumentException('Configuration path cannot be empty.');
        }

        if (!file_exists($path)) {
            throw new \InvalidArgumentException(sprintf('Configuration file "%s" does not exist.', $path));
        }

        if (!is_readable($path)) {
            throw new \InvalidArgumentException(sprintf('Configuration file "%s" is not readable.', $path));
        }

        $config = require $path;

        if (!is_array($config)) {
            throw new \InvalidArgumentException(
                sprintf('Configuration file "%s" must return a PHP array.', $path)
            );
        }

        return self::validate($config);
    }

    /**
     * Validates and merges defaults into the provided configuration.
     *
     * Guarantees that all keys used by Shield::protect(), middleware,
     * protectors and detectors are present with safe defaults.
     *
     * @param array<string, mixed> $config User-provided configuration
     * @return array<string, mixed> Normalized configuration with all required keys
     * @throws \InvalidArgumentException On any invalid value with a helpful message
     */
    public static function validate(array $config): array
    {
        $defaults = [
            'secret' => '',
            'validator' => 'hmac-sha256',
            'tolerance' => 300,
            'rate_limit' => [
                'max' => 100,
                'window' => 60,
            ],
            'cache' => new ArrayAdapter(),
            'rules' => [],
            'signature' => [
                'header' => 'x-signature',
                'prefix' => '',
            ],
            'logger' => null,
            'router' => null,
        ];

        /** @var array<string, mixed> $config */
        $config = array_replace_recursive($defaults, $config);

        if (!is_string($config['secret'])) {
            throw new \InvalidArgumentException('The "secret" configuration value must be a string.');
        }

        if (!is_string($config['validator'])) {
            throw new \InvalidArgumentException('The "validator" must be a string (hmac-sha256 or rsa-pss).');
        }

        $validValidators = ['hmac-sha256', 'hmac', 'rsa-pss', 'rsa'];
        if (!in_array(strtolower($config['validator']), $validValidators, true)) {
            throw new \InvalidArgumentException(
                sprintf(
                    'Unknown validator "%s". Allowed values: hmac-sha256, rsa-pss.',
                    $config['validator']
                )
            );
        }

        if (!is_int($config['tolerance']) || $config['tolerance'] < 30) {
            throw new \InvalidArgumentException(
                'The "tolerance" must be an integer >= 30 (seconds).'
            );
        }

        if (!is_array($config['rate_limit'])) {
            throw new \InvalidArgumentException('The "rate_limit" configuration must be an array.');
        }

        if (!isset($config['rate_limit']['max']) || !is_int($config['rate_limit']['max']) || $config['rate_limit']['max'] < 1) {
            throw new \InvalidArgumentException(
                'rate_limit.max must be a positive integer.'
            );
        }

        if (!isset($config['rate_limit']['window']) || !is_int($config['rate_limit']['window']) || $config['rate_limit']['window'] < 1) {
            throw new \InvalidArgumentException(
                'rate_limit.window must be a positive integer (seconds).'
            );
        }

        if (!$config['cache'] instanceof CacheItemPoolInterface) {
            throw new \InvalidArgumentException(
                'The "cache" must be an instance of CacheItemPoolInterface (e.g. ArrayAdapter, RedisAdapter).'
            );
        }

        if (!is_array($config['rules'])) {
            throw new \InvalidArgumentException('The "rules" configuration must be an array of callables.');
        }

        foreach ($config['rules'] as $index => $rule) {
            if (!is_callable($rule)) {
                throw new \InvalidArgumentException(
                    sprintf('rules[%d] must be callable (received %s).', $index, get_debug_type($rule))
                );
            }
        }

        if (!is_array($config['signature'])) {
            throw new \InvalidArgumentException('The "signature" configuration must be an array.');
        }

        if (!isset($config['signature']['header']) || !is_string($config['signature']['header'])) {
            throw new \InvalidArgumentException('signature.header must be a non-empty string.');
        }

        if (!isset($config['signature']['prefix']) || !is_string($config['signature']['prefix'])) {
            throw new \InvalidArgumentException('signature.prefix must be a string.');
        }

        if ($config['logger'] !== null && !$config['logger'] instanceof LoggerInterface) {
            throw new \InvalidArgumentException(
                'The "logger" must be an instance of LoggerInterface or null.'
            );
        }

        if ($config['router'] !== null && !$config['router'] instanceof EventRouter) {
            throw new \InvalidArgumentException(
                'The "router" must be an instance of EventRouter or null.'
            );
        }

        return $config;
    }
}

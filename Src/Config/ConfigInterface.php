<?php declare(strict_types=1);

namespace Temant\AuthManager\Config {
    /**
     * Interface ConfigInterface
     *
     * This interface defines methods to interact with a configuration storage.
     * Configurations are key-value pairs used to manage settings and options.
     *
     * @version 1.0.0
     * @since   2023-08-29
     * @author  Emad Almahdi
     */
    interface ConfigInterface
    {
        /**
         * Get a configuration value by key.
         *
         * @param string $key   The key of the configuration value.
         * @return ?string      The configuration value associated with the key, or null if not found.
         */
        public function get(string $key): ?string;

        /**
         * Set a configuration value.
         *
         * @param string $key   The key for the configuration value.
         * @param string $value The value to set for the configuration.
         * @return bool         True on successful setting, false if there was an issue.
         */
        public function set(string $key, string $value): bool;

        /**
         * Update a configuration value.
         *
         * @param string $key   The key of the configuration value to update.
         * @param string $value The new value to update for the configuration.
         * @return bool         True on successful update, false if the key doesn't exist.
         */
        public function update(string $key, string $value): bool;

        /**
         * Check if a configuration key exists.
         *
         * @param string $key   The key to check for existence.
         * @return bool         True if the key exists, false otherwise.
         */
        public function has(string $key): bool;

        /**
         * Get all configuration values as an array.
         *
         * @return array        An associative array of all configuration key-value pairs.
         */
        public function all(): array;
    }
}
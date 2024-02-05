<?php declare(strict_types=1);

namespace Temant\AuthManager {

    interface TokenManagerInterface
    {
        /**
         * Generates a secure, unique authentication token with a selector for identification and a validator for security.
         *
         * @return string[] An array containing the selector, the hashed validator, and the full token string.
         */
        public static function generateToken(): array;

        /**
         * Splits a token into its selector and validator components.
         *
         * @param string $token The full token string to be parsed.
         * @return string[]|null An array with selector and validator if the format is correct, null otherwise.
         */
        public static function parseToken(string $token): ?array;

        /**
         * Persists a token in the storage with its associated user, type, and validity period.
         *
         * @param string $userId The ID of the user owning the token.
         * @param string $type The token's purpose, e.g., 'session' or 'reset'.
         * @param string $selector The token's lookup identifier.
         * @param string $validator The hashed token validator for security.
         * @param int $days The token's lifespan in days, defaulting to 1 day.
         * @return bool True if storage is successful, false otherwise.
         */
        public function saveToken(string $userId, string $type, string $selector, string $validator, int $days = 1): bool;

        /**
         * Removes tokens from the storage based on given conditions, or all tokens if no conditions are specified.
         *
         * @param array<string, mixed>|null $conditions Optional key-value pairs for filtering tokens to be deleted.
         * @return bool True if removal is successful, false otherwise.
         */
        public function removeToken(?array $conditions = null): bool;

        /**
         * Fetches a token from storage by its selector, ensuring it's still valid (not expired).
         *
         * @param string $selector The token's unique identifier.
         * @return string[]|null Token data if available and valid, null otherwise.
         */
        public function getTokenBySelector(string $selector): ?array;

        /**
         * Checks the validity of a token by comparing its provided validator against the stored hashed validator.
         *
         * @param string $token The token to validate.
         * @return bool True if valid, false otherwise.
         */
        public function isValid(string $token): bool;
        /**
         * Refreshes an existing token by generating a new one while retaining the same selector.
         *
         * @param string $token The current token to be refreshed.
         * @param int $days The validity period of the new token in days.
         * @return ?string The new token if refresh is successful, null otherwise.
         */
        public function refreshToken(string $token, int $days = 1): ?string;

        /**
         * Removes all tokens associated with a given user ID, useful for user logout or account deactivation scenarios.
         *
         * @param string $userId The ID of the user whose tokens are to be removed.
         * @return bool True if tokens are successfully removed, false otherwise.
         */
        public function removeAllTokensForUser(string $userId): bool;

        /**
         * Checks if a token is expired based on its expiry date without accessing the database.
         *
         * @param string $expiryDate The expiry date of the token in 'Y-m-d H:i:s' format.
         * @return bool True if the token is expired, false otherwise.
         */
        public static function isTokenExpired(string $expiryDate): bool;

        /**
         * Performs a cleanup operation to remove expired tokens from the storage, optimizing database usage.
         */
        public function cleanupExpiredTokens(): void;
    }
}
<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use Temant\AuthManager\Storage\StorageInterface;

    /**
     * Handles all aspects of authentication token lifecycle management within the system.
     * 
     * The TokenManager class is responsible for the creation, storage, retrieval, validation, and deletion of authentication tokens,
     * offering a secure mechanism to manage user sessions and other forms of token-based authentication. It interfaces with a
     * storage backend, abstracted through the StorageInterface, to persist token data. This allows for flexible storage implementations
     * and ensures that the TokenManager can adapt to various storage environments.
     * 
     * Key functionalities include:
     * - Token Generation: Creates unique, secure tokens composed of a selector (for lookup) and a validator (for verification).
     * - Token Parsing: Extracts the selector and validator from a token string, facilitating validation and other operations.
     * - Token Storage: Saves tokens with associated user details and expiry information in the storage system.
     * - Token Retrieval: Fetches tokens from storage based on selectors, ensuring they are still valid (not expired).
     * - Token Validation: Verifies the authenticity and validity of tokens by comparing provided validators against stored values.
     * - Token Refresh: Generates a new token while retaining the original selector, extending the validity period without full re-authentication.
     * - Token Cleanup: Removes expired tokens from storage to maintain database efficiency and security.
     * 
     * This class is designed to be flexible and secure, encapsulating the complexities of token management and providing a straightforward
     * interface for authentication processes within the application.
     */
    class TokenManager implements TokenManagerInterface
    {
        private const DAY_IN_SECONDS = 86400; // Represents the number of seconds in a day for token expiry calculation.

        /**
         * Initializes the TokenManager with a storage mechanism for token persistence.
         *
         * @param StorageInterface $storage A storage implementation instance for managing authentication tokens.
         */
        public function __construct(
            private StorageInterface $storage
        ) {
        }

        /**
         * Generates a secure, unique authentication token with a selector for identification and a validator for security.
         *
         * @return string[] An array containing the selector, the hashed validator, and the full token string.
         */
        public static function generateToken(): array
        {
            $selector = bin2hex(random_bytes(16)); // Unique identifier for database lookup.
            $validator = bin2hex(random_bytes(32)); // Random string for validation.
            $hashedValidator = password_hash($validator, PASSWORD_DEFAULT); // Securely hashed validator.
            return [$selector, $hashedValidator, "$selector:" . $validator];
        }

        /**
         * Splits a token into its selector and validator components.
         *
         * @param string $token The full token string to be parsed.
         * @return string[]|null An array with selector and validator if the format is correct, null otherwise.
         */
        public static function parseToken(string $token): ?array
        {
            $parts = explode(':', $token);
            return count($parts) === 2 ? $parts : null; // Validates token format.
        }

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
        public function saveToken(string $userId, string $type, string $selector, string $validator, int $days = 1): bool
        {
            return $this->storage->insertRow('auth_token', [
                'user_id' => $userId,
                'type' => $type,
                'selector' => $selector,
                'validator' => $validator,
                'expires_at' => $this->calculateExpiry($days)
            ]);
        }

        /**
         * Removes tokens from the storage based on given conditions, or all tokens if no conditions are specified.
         *
         * @param array<string, mixed>|null $conditions Optional key-value pairs for filtering tokens to be deleted.
         * @return bool True if removal is successful, false otherwise.
         */
        public function removeToken(?array $conditions = null): bool
        {
            return $this->storage->removeRow('auth_token', $conditions ?: []);
        }

        /**
         * Fetches a token from storage by its selector, ensuring it's still valid (not expired).
         *
         * @param string $selector The token's unique identifier.
         * @return string[]|null Token data if available and valid, null otherwise.
         */
        public function getTokenBySelector(string $selector): ?array
        {
            return $this->storage->getRow('auth_token', [
                'selector' => $selector,
                'expires_at' => [date('Y-m-d H:i:s'), '>=']
            ]);
        }

        /**
         * Checks the validity of a token by comparing its provided validator against the stored hashed validator.
         *
         * @param string $token The token to validate.
         * @return bool True if valid, false otherwise.
         */
        public function isValid(string $token): bool
        {
            [$selector, $validator] = self::parseToken($token) ?: ['', ''];
            $tokenData = $this->getTokenBySelector($selector);
            return isset($tokenData['validator']) && password_verify($validator, $tokenData['validator']);
        }

        /**
         * Refreshes an existing token by generating a new one while retaining the same selector.
         *
         * @param string $token The current token to be refreshed.
         * @param int $days The validity period of the new token in days.
         * @return ?string The new token if refresh is successful, null otherwise.
         */
        public function refreshToken(string $token, int $days = 1): ?string
        {
            if (!$this->isValid($token)) {
                return null;
            }

            [$selector,] = self::parseToken($token);
            [$newSelector, $newValidator, $newToken] = self::generateToken();
            if ($this->saveToken($newSelector, 'refresh', $selector, $newValidator, $days)) {
                return $newToken;
            }

            return null;
        }

        /**
         * Removes all tokens associated with a given user ID, useful for user logout or account deactivation scenarios.
         *
         * @param string $userId The ID of the user whose tokens are to be removed.
         * @return bool True if tokens are successfully removed, false otherwise.
         */
        public function removeAllTokensForUser(string $userId): bool
        {
            return $this->removeToken(['user_id' => $userId]);
        }

        /**
         * Checks if a token is expired based on its expiry date without accessing the database.
         *
         * @param string $expiryDate The expiry date of the token in 'Y-m-d H:i:s' format.
         * @return bool True if the token is expired, false otherwise.
         */
        public static function isTokenExpired(string $expiryDate): bool
        {
            return strtotime($expiryDate) < time();
        }

        /**
         * Calculates the expiry date for a token based on the specified number of days from the current time.
         *
         * @param int $days The number of days until the token should expire.
         * @return string The calculated expiry date in 'Y-m-d H:i:s' format.
         */
        private function calculateExpiry(int $days): string
        {
            return date('Y-m-d H:i:s', time() + self::DAY_IN_SECONDS * $days);
        }

        /**
         * Performs a cleanup operation to remove expired tokens from the storage, optimizing database usage.
         */
        public function cleanupExpiredTokens(): void
        {
            $this->removeToken(['expires_at' => [date('Y-m-d H:i:s'), '<']]);
        }
    }
}
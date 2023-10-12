<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use Temant\AuthManager\Storage\StorageInterface;

    /**
     * The TokenManager class provides methods for generating, parsing, saving, and validating authentication tokens.
     */
    class TokenManager
    {
        /**
         * TokenManager constructor.
         *
         * @param StorageInterface $storage The storage implementation used to store authentication tokens.
         */
        public function __construct(
            private StorageInterface $storage
        ) {
        }

        /**
         * Generates a new authentication token consisting of a selector and a validator.
         *
         * @return array An array containing the selector, validator, and the combined token as elements.
         */
        public static function generateToken(): array
        {
            return [
                $selector = bin2hex(random_bytes(16)),
                $validator = password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT),
                "$selector:$validator"
            ];
        }

        /**
         * Parses an authentication token into its selector and validator components.
         *
         * @param string $token The authentication token to be parsed.
         *
         * @return ?array An array with two elements (selector and validator) if the token is valid, or null if it cannot be parsed.
         */
        public static function parseToken(string $token): ?array
        {
            $parts = explode(':', $token);

            return (count($parts) === 2) ? $parts : null;
        }

        /**
         * Saves an authentication token in the storage.
         *
         * @param string $userId   The user ID associated with the token.
         * @param string $type     The type of token (e.g., session token, password reset token).
         * @param string $selector The unique selector for the token.
         * @param string $validator The token validator.
         * @param int    $days     (Optional) The number of days for which the token should be valid (default is 1 day).
         *
         * @return bool True if the token is successfully saved, false otherwise.
         */
        public function saveToken(string $userId, string $type, string $selector, string $validator, int $days = 1): bool
        {
            return $this->storage
                ->insertRow('auth_token', [
                    'user_id' => $userId,
                    'selector' => $selector,
                    'validator' => $validator,
                    'type' => $type,
                    'expires_at' => date('Y-m-d H:i:s', time() + 60 * 60 * 24 * $days)
                ]);
        }

        /**
         * Removes authentication tokens from the storage based on specified conditions.
         *
         * @param ?array $conditions (Optional) Conditions to filter the tokens to be removed (if not provided, all tokens will be removed).
         *
         * @return bool True if the tokens are successfully removed, false otherwise.
         */
        public function removeToken(?array $conditions = null): bool
        {
            return $this->storage->removeRow('auth_token', $conditions);
        }

        /**
         * Retrieves an authentication token from the storage based on its selector and checks if it has not expired.
         *
         * @param string $selector The selector used to identify the token.
         *
         * @return ?array An array containing the token data if found and not expired, or null otherwise.
         */
        public function getTokenBySelector(string $selector): ?array
        {
            return $this->storage->getRow('auth_token', [
                'selector' => $selector,
                'expires_at' => [date('Y-m-d H:i:s', time()), '>=']
            ]);
        }

        /**
         * Validates if a given authentication token is valid by comparing its validator with the stored validator.
         *
         * @param string $token The authentication token to be validated.
         *
         * @return bool True if the token is valid, false otherwise.
         */
        public function isValid(string $token): bool
        {
            [$selector, $validator] = TokenManager::parseToken($token);
            $tokens = $this->getTokenBySelector($selector);
            if (isset($tokens['validator'])) {
                return $validator === $tokens['validator'];
            }
            return false;
        }
    }
}
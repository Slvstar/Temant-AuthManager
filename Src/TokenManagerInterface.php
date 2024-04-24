<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTime;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;

    interface TokenManagerInterface
    {
        /**
         * Generates a secure, unique authentication token,
         * consisting of a selector for identification and a hashed validator for verification.
         *
         * @return string[] An array containing the selector, hashed validator, and the full token string.
         */
        public function generateToken(): array;

        /**
         * Decomposes a token into its constituent selector and validator components.
         *
         * @param string $token The complete token string to be dissected.
         * @return string[]|null An array containing the selector and validator, or null if the format is incorrect.
         */
        public function parseToken(string $token): ?array;

        /**
         * Stores a token in the database along with associated user information and expiration details.
         *
         * @param User $user Identifier of the user associated with the token.
         * @param string $type Purpose of the token (e.g., 'session', 'reset').
         * @param string $selector Token's unique identifier for lookup.
         * @param string $validator Hashed validator part of the token for security.
         * @param int $days Lifespan of the token in days, defaults to 1 day.
         * @return bool Returns true upon successful storage, otherwise false.
         */
        public function saveToken(User $user, string $type, string $selector, string $validator, int $days = 1): bool;

        /**
         * Deletes tokens from the database based on specified conditions or all tokens if no conditions are provided.
         *
         * @param array<string, mixed> $conditions Key-value pairs for filtering which tokens to delete.
         * @return int Number of tokens deleted.
         */
        public function removeToken(array $conditions): int;


        /**
         * Retrieves a token from the database using its selector, verifying that it hasn't expired.
         *
         * @param string $selector Unique identifier of the token.
         * @return string[]|null Returns token data if found and valid, otherwise null.
         */
        public function getTokenBySelector(string $selector): ?array;

        /**
         * Validates a token by matching the provided validator against the stored hashed validator.
         *
         * @param string $token The token to validate.
         * @return bool Returns true if the token is valid, otherwise false.
         */
        public function isValid(string $token): bool;

        /**
         * List all tokens associated with a specific user ID.
         *
         * @param string $userId User ID whose tokens are to be listed.
         * @return Token[] A list of tokens or empty array
         */
        public function listAllTokensForUser(string $userId): array;

        /**
         * Deletes all tokens associated with a specific user ID, commonly used for logging out or account deactivation.
         *
         * @param string $userId User ID whose tokens are to be deleted.
         * @return int Number of tokens deleted.
         */
        public function removeAllTokensForUser(string $userId): int;

        /**
         * Determines if a token is expired based on its stored expiry date.
         *
         * @param string $expiryDate Token's expiry date in 'Y-m-d H:i:s' format.
         * @return bool Returns true if the token is expired, otherwise false.
         */
        public static function isTokenExpired(?DateTime $expiryDate): bool;

        /**
         * Removes expired tokens from the database to maintain efficiency and security.
         *
         * @return int Number of tokens deleted.
         */
        public function cleanupExpiredTokens(): int;
    }
}
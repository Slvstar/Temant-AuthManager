<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;

    /**
     * TokenManagerInterface defines the contract for managing authentication tokens.
     * It provides methods for generating, storing, validating, retrieving, and deleting tokens.
     * This interface is designed to facilitate secure session management and authentication workflows.
     */
    interface TokenManagerInterface
    {
        public const int VALIDATOR_HASH_COST = 12;

        /**
         * Generates a secure and unique authentication token.
         * 
         * The token is composed of two parts: a selector for quick identification and a validator for security.
         * The validator is hashed for secure storage, ensuring that raw values are not exposed.
         *
         * @return string[] An array containing:
         *                  - string $selector: The unique identifier for the token.
         *                  - string $hashedValidator: The securely hashed validator for verification.
         *                  - string $token: The full token string in the format "selector:validator".
         */
        public function generateToken(): array;

        /**
         * Decomposes a token string into its constituent selector and validator components.
         * 
         * This method expects a token in the format "selector:validator" and splits it into its respective parts.
         *
         * @param string $token The full token string to be parsed.
         * @return string[]|null An array containing the selector and validator, or null if the token format is invalid.
         */
        public function parseToken(string $token): ?array;

        /**
         * Stores a token in the database, associating it with a specific user and setting its expiration.
         * 
         * The token is saved with a defined lifespan, after which it becomes invalid.
         * This method is crucial for managing sessions and other token-based operations.
         *
         * @param User $user The user associated with the token.
         * @param string $type The type of token (e.g., 'session', 'reset').
         * @param string $selector The unique selector part of the token for quick lookup.
         * @param string $validator The hashed validator part of the token for security.
         * @param int $seconds The lifespan of the token in seconds.
         * @return bool True if the token was successfully stored, false otherwise.
         */
        public function saveToken(User $user, string $type, string $selector, string $validator, int $seconds): bool;

        /**
         * Deletes tokens from the database based on specified conditions.
         * 
         * This method allows for targeted removal of tokens, such as those belonging to a specific user or those that have expired.
         *
         * @param array<string, mixed> $conditions An associative array of field names and values to filter which tokens to delete.
         * @return int The number of tokens deleted from the database.
         */
        public function removeToken(array $conditions): int;

        /**
         * Retrieves a token from the database using its selector, verifying that it hasn't expired.
         * 
         * This method is used to retrieve a specific token based on its unique selector.
         * If the token is found and has not expired, it is returned; otherwise, null is returned.
         *
         * @param string $selector The unique identifier of the token.
         * @return Token|null The Token entity if found and valid, otherwise null.
         */
        public function getTokenBySelector(string $selector): ?Token;

        /**
         * Validates a token by verifying the provided validator against the stored hashed validator.
         * 
         * This method ensures that the token is authentic and has not expired.
         * It checks the token's components and compares the hashed validator for security.
         *
         * @param string $token The full token string to be validated.
         * @return bool True if the token is valid and has not expired, false otherwise.
         */
        public function isValid(string $token): bool;

        /**
         * Lists all tokens associated with a specific user.
         * 
         * This method retrieves all tokens belonging to a user, typically used for session management or audit purposes.
         *
         * @param User $user The user whose tokens are to be listed.
         * @return Token[] An array of Token entities associated with the user.
         */
        public function listAllTokensForUser(User $user): array;

        /**
         * Deletes all tokens associated with a specific user.
         * 
         * This method is commonly used for operations like logging out, where all active tokens for a user need to be invalidated.
         *
         * @param User $user The user whose tokens are to be deleted.
         * @return int The number of tokens that were deleted.
         */
        public function removeAllTokensForUser(User $user): int;
    }
}
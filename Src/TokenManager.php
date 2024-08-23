<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTime;
    use Doctrine\DBAL\Types\Types;
    use Doctrine\ORM\EntityManagerInterface;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;

    /**
     * The TokenManager class handles the lifecycle of authentication tokens,
     * including creation, storage, retrieval, validation, and deletion.
     * This class is built on Doctrine's EntityManager to manage database operations,
     * providing an object-oriented interface for working with token data.
     * It plays a crucial role in maintaining secure and efficient session management within an application.
     */
    class TokenManager implements TokenManagerInterface
    {
        /**
         * Constructs the TokenManager and immediately performs cleanup of expired tokens to maintain system integrity.
         *
         * @param EntityManagerInterface $entityManager EntityManager instance for managing token entities.
         */
        public function __construct(private EntityManagerInterface $entityManager)
        {
            $this->cleanupExpiredTokens();
        }

        /**
         * Generates a secure and unique authentication token.
         * 
         * The token is divided into two components: a selector for easy identification
         * and a validator for security, which is securely hashed before storage.
         *
         * @return string[] An array containing:
         *                  - string $selector: The unique identifier for the token.
         *                  - string $hashedValidator: The hashed version of the validator used for security checks.
         *                  - string $token: The full token string composed of selector and raw validator.
         */
        public function generateToken(): array
        {
            $selector = bin2hex(random_bytes(16));
            $validator = bin2hex(random_bytes(32));
            $hashedValidator = password_hash($validator, PASSWORD_DEFAULT, ['cost' => self::VALIDATOR_HASH_COST]);

            return [$selector, $hashedValidator, "$selector:$validator"];
        }

        /**
         * Retrieves all tokens associated with a specific user and token type.
         *
         * @param User $user The user for whom tokens are to be retrieved.
         * @param string $type The type of tokens to retrieve (e.g., 'session', 'reset').
         * @return Token[] An array of Token entities associated with the user and type.
         */
        public function findByUserAndType(User $user, string $type): array
        {
            return $this->entityManager->getRepository(Token::class)
                ->findBy(['user' => $user, 'type' => $type]);
        }

        /**
         * Removes all tokens of a specified type for a given user.
         *
         * @param User $user The user whose tokens are to be removed.
         * @param string $type The type of tokens to remove (e.g., 'session', 'reset').
         * @return int The number of tokens that were removed.
         */
        public function removeTokensForUserByType(User $user, string $type): int
        {
            $tokens = $this->findByUserAndType($user, $type);
            foreach ($tokens as $token) {
                $this->entityManager->remove($token);
            }
            $this->entityManager->flush();

            return count($tokens);
        }

        /**
         * Parses a token string into its constituent parts.
         *
         * The token string is expected to be in the format "selector:validator".
         * This method extracts the selector and validator for further processing.
         *
         * @param string $token The token string to be parsed.
         * @return string[]|null An array containing the selector and validator, or null if the format is invalid.
         */
        public function parseToken(string $token): ?array
        {
            $parts = explode(':', $token);
            return count($parts) === 2 ? $parts : null;
        }

        /**
         * Stores a newly generated token in the database.
         * 
         * This method associates the token with a specific user and sets its expiration time.
         * The token is then persisted to the database for future validation.
         *
         * @param User $user The user for whom the token is being generated.
         * @param string $type The type of token (e.g., 'session', 'reset').
         * @param string $selector The selector part of the token used for quick lookup.
         * @param string $validator The hashed validator part of the token for security.
         * @param int $seconds The duration in seconds for which the token remains valid. Defaults to 86400 seconds (1 day).
         * @return bool True if the token was successfully stored, otherwise false.
         */
        public function saveToken(User $user, string $type, string $selector, string $validator, int $seconds = 86400): bool
        {
            $token = (new Token())
                ->setUser($user)
                ->setType($type)
                ->setSelector($selector)
                ->setValidator($validator)
                ->setExpiresAt((new DateTime())->setTimestamp(time() + $seconds));

            $this->entityManager->persist($token);
            $this->entityManager->flush();

            return $this->entityManager->contains($token);
        }

        /**
         * Deletes tokens based on specified conditions.
         * 
         * This method allows for the removal of tokens that match specific criteria, such as a particular selector or user ID.
         *
         * @param array<string, mixed> $conditions An associative array of field names and values to filter tokens for deletion.
         * @return int The number of tokens deleted from the database.
         */
        public function removeToken(array $conditions): int
        {
            $query = $this->entityManager
                ->createQueryBuilder()
                ->delete(Token::class, 't');

            foreach ($conditions as $field => $value) {
                $query->andWhere("t.$field = :$field")
                    ->setParameter($field, $value);
            }

            return $query->getQuery()->execute();
        }

        /**
         * Retrieves a token from the database using its selector.
         * 
         * This method allows for the quick lookup of a token based on its unique selector.
         *
         * @param string $selector The selector part of the token used to retrieve it from the database.
         * @return Token|null The Token entity if found, or null if no matching token is found.
         */
        public function getTokenBySelector(string $selector): ?Token
        {
            return $this->entityManager
                ->getRepository(Token::class)
                ->findOneBy(['selector' => $selector]);
        }

        /**
         * Validates a token by checking its authenticity and expiration status.
         * 
         * This method first parses the token, then retrieves the corresponding token entity
         * from the database using the selector. It verifies the validator against the stored
         * hashed validator and checks if the token has expired.
         *
         * @param string $token The full token string to be validated.
         * @return bool True if the token is valid and not expired, otherwise false.
         */
        public function isValid(string $token): bool
        {
            [$selector, $validator] = $this->parseToken($token) ?? [null, null];
            if (!$selector || !$validator) {
                return false;
            }
            $tokenData = $this->getTokenBySelector($selector);

            return $tokenData &&
                password_verify($validator, $tokenData->getValidator()) &&
                !$this->hasTokenExpired($tokenData->getExpiresAt());
        }

        /**
         * Removes all tokens associated with a specific user.
         * 
         * This method is typically used when a user logs out or their account is deactivated.
         *
         * @param User $user The user whose tokens are to be deleted.
         * @return int The number of tokens deleted.
         */
        public function removeAllTokensForUser(User $user): int
        {
            $count = 0;
            $user->getTokens()->map(function (Token $token) use (&$count): void {
                $this->entityManager->remove($token);
                $count++;
            });

            $this->entityManager->flush();

            return $count;
        }

        /**
         * Lists all tokens associated with a specific user.
         *
         * @param User $user The user whose tokens are to be listed.
         * @return Token[] An array of Token entities associated with the user.
         */
        public function listAllTokensForUser(User $user): array
        {
            return $user->getTokens()->toArray();
        }

        /**
         * Checks if a token has expired based on its expiry date.
         * 
         * This method compares the token's expiration date with the current date and time.
         *
         * @param DateTime $expiryDate The expiration date of the token.
         * @return bool True if the token is expired, otherwise false.
         */
        private function hasTokenExpired(DateTime $expiryDate): bool
        {
            return $expiryDate < new DateTime();
        }

        /**
         * Cleans up expired tokens from the database to improve security and performance.
         * 
         * This method automatically removes tokens that have passed their expiration date,
         * reducing the risk of old tokens being exploited and keeping the database optimized.
         *
         * @return int The number of expired tokens deleted from the database.
         */
        private function cleanupExpiredTokens(): int
        {
            return $this->entityManager
                ->createQueryBuilder()
                ->delete(Token::class, 't')
                ->where('t.expiresAt < :currentDateTime')
                ->setParameter('currentDateTime', new DateTime(), Types::DATETIME_MUTABLE)
                ->getQuery()
                ->execute();
        }

        /**
         * Retrieves detailed information about a token, including its validity status.
         * 
         * This method provides a comprehensive overview of a token, including its raw and hashed
         * components, its current status (active or expired), and the remaining time until expiration.
         *
         * @param string $token The full token string to be examined.
         * @return array An associative array containing:
         *               - string $token: The original token string.
         *               - string $selector: The selector component of the token.
         *               - string $real_validator: The raw validator component of the token.
         *               - string $hashed_validator: The stored hashed validator for verification.
         *               - bool $is_active: Whether the token is currently valid and active.
         *               - int $expires_after: The number of seconds remaining before the token expires.
         */
        public function getToken(string $token): array
        {
            [$selector, $realValidator] = $this->parseToken($token);

            $tokenData = $this->getTokenBySelector($selector);

            return [
                'token' => $token,
                'selector' => $selector,
                'real_validator' => $realValidator,
                'hashed_validator' => $tokenData ? $tokenData->getValidator() : null,
                'is_active' => $this->isValid($token),
                'expires_after' => $tokenData ? $tokenData->getExpiresAt()->getTimestamp() - time() : null
            ];
        }
    }
}
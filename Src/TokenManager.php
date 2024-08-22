<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTime;
    use Doctrine\DBAL\Types\Types;
    use Doctrine\ORM\EntityManagerInterface;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;

    /**
     * Manages authentication tokens throughout their lifecycle, including creation, storage, retrieval, validation, and deletion.
     * This class leverages Doctrine's EntityManager for interaction with the database, allowing for object-oriented data management
     * and abstracting direct database access. It supports various token-related operations essential for secure authentication
     * and session management within applications.
     */
    class TokenManager implements TokenManagerInterface
    {
        /**
         * Initializes the TokenManager with Doctrine's EntityManager for database operations.
         *
         * @param EntityManagerInterface $entityManager EntityManager instance for managing token entities.
         */
        public function __construct(
            private EntityManagerInterface $entityManager
        ) {
        }

        /**
         * Generates a secure, unique authentication token,
         * consisting of a selector for identification and a hashed validator for verification.
         *
         * @return string[] An array containing the selector, hashed validator, and the full token string.
         */
        public function generateToken(): array
        {
            // Unique identifier for database lookup.
            $selector = bin2hex(random_bytes(16));
            // Random string for validation.
            $validator = bin2hex(random_bytes(32));
            // Securely hashed validator.
            $hashedValidator = password_hash($validator, PASSWORD_DEFAULT);
            return [$selector, $hashedValidator, "$selector:$validator"];
        }

        /**
         * Finds tokens for a specific user and type.
         *
         * @param User $user The ID of the user.
         * @param string $type The type of tokens to find.
         * @return Token[] An array of Token entities for the given user.
         */
        public function findByUserAndType(User $user, string $type): array
        {
            return $user->getTokens()
                ->filter(fn($token): bool => $token->getType() === $type)
                ->toArray();
        }

        public function removeTokensForUserByType(User $user, string $type)
        {
            $tokens = $this->findByUserAndType($user, $type);
            foreach ($tokens as $token) {
                $this->entityManager->remove($token);
                $this->entityManager->flush();
            }
        }

        /**
         * Decomposes a token into its constituent selector and validator components.
         *
         * @param string $token The complete token string to be dissected.
         * @return string[]|null An array containing the selector and validator, or null if the format is incorrect.
         */
        public function parseToken(string $token): ?array
        {
            $parts = explode(':', $token);
            return count($parts) === 2 ? $parts : null;
        }

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
        public function saveToken(User $user, string $type, string $selector, string $validator, int $days = 1): bool
        {
            $token = (new Token())
                ->setUser($user)
                ->setType($type)
                ->setSelector($selector)
                ->setValidator($validator)
                ->setExpiresAt(new DateTime("+{$days} days"));

            $this->entityManager->persist($token);
            $this->entityManager->flush();

            return $this->entityManager->contains($token);
        }

        /**
         * Deletes tokens from the database based on specified conditions or all tokens if no conditions are provided.
         *
         * @param array<string, mixed> $conditions Key-value pairs for filtering which tokens to delete.
         * @return int Number of tokens deleted.
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
         * @param string $selector Unique identifier of the token.
         * @return Token|null Returns token data if found and valid, otherwise null.
         */
        public function getTokenBySelector(string $selector): Token|null
        {
            return $this->entityManager
                ->getRepository(Token::class)
                ->findOneBy(['selector' => $selector]);
        }

        /**
         * Validates a token by matching the provided validator against the stored hashed validator.
         * Also checks if the token has expired.
         *
         * @param string $token The token to validate.
         * @return bool Returns true if the token is valid and not expired, otherwise false.
         */
        public function isValid(string $token): bool
        {
            [$selector, $validator] = $this->parseToken($token) ?? [null, null];
            $tokenData = $this->getTokenBySelector($selector);

            return $tokenData &&
                password_verify($validator, $tokenData->getValidator()) &&
                !$this->hasTokenExpired($tokenData->getExpiresAt());
        }

        /**
         * Deletes all tokens associated with a specific user, commonly used for logging out or account deactivation.
         *
         * @param User $user User whose tokens are to be deleted.
         * @return int Number of tokens deleted.
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
         * List all tokens associated with a specific user ID.
         *
         * @param User $user User whose tokens are to be listed.
         * @return Token[] A list of tokens or empty array
         */
        public function listAllTokensForUser(User $user): array
        {
            return $user->getTokens()->toArray();
        }

        /**
         * Determines if a token is expired based on its stored expiry date.
         *
         * @param DateTime $expiryDate Token's expiry date in 'Y-m-d H:i:s' format.
         * @return bool Returns true if the token is expired, otherwise false.
         */
        private function hasTokenExpired(DateTime $expiryDate): bool
        {
            return $expiryDate < new DateTime;
        }

        /**
         * Removes expired tokens from the database to maintain efficiency and security.
         *
         * @return int Number of tokens deleted.
         */
        public function cleanupExpiredTokens(): int
        {
            return $this->entityManager
                ->createQueryBuilder()
                ->delete(Token::class, 't')
                ->where('t.expiresAt < :currentDateTime')
                ->setParameter('currentDateTime', new DateTime(), Types::DATETIME_MUTABLE)
                ->getQuery()
                ->execute();
        }
    }
}
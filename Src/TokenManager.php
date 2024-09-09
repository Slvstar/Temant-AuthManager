<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTime;
    use Doctrine\DBAL\Types\Types;
    use Doctrine\ORM\EntityManagerInterface;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;

    /**
     * Manages the lifecycle of authentication tokens including their creation, retrieval, validation, and deletion,
     * leveraging Doctrine's EntityManager for database interactions.
     */
    class TokenManager
    {
        /**
         * @var int Specifies the bcrypt hash cost for token validation.
         */
        public const int VALIDATOR_HASH_COST = 12;

        /**
         * Initializes the TokenManager and cleans up expired tokens.
         *
         * @param EntityManagerInterface $entityManager Handles database operations for tokens.
         */
        public function __construct(private EntityManagerInterface $entityManager)
        {
            $this->cleanupExpiredTokens();
        }

        /**
         * Generates a new secure authentication token with distinct selector and validator components.
         *
         * @return string[] Array containing the selector, hashed validator, and concatenated token string.
         */
        public function generateToken(): array
        {
            $selector = bin2hex(random_bytes(16));
            $validator = bin2hex(random_bytes(32));
            $hashedValidator = password_hash($validator, PASSWORD_DEFAULT, ['cost' => self::VALIDATOR_HASH_COST]);

            return [$selector, $hashedValidator, "$selector:$validator"];
        }

        /**
         * Retrieves tokens for a user based on type (e.g., 'session', 'reset').
         *
         * @param User $user The user whose tokens are being queried.
         * @param string $type The type of tokens to retrieve.
         * @return Token[] Array of associated Token entities.
         */
        public function findByUserAndType(User $user, string $type): array
        {
            return $this->entityManager->getRepository(Token::class)
                ->findBy(['user' => $user, 'type' => $type]);
        }

        /**
         * Deletes tokens of a specified type for a user.
         *
         * @param User $user The user whose tokens are to be deleted.
         * @param string $type The type of tokens to delete.
         * @return int Number of tokens removed.
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
         * Parses a token string into selector and validator components.
         *
         * @param string $token The full token string.
         * @return string[]|null Selector and validator if valid, otherwise null.
         */
        public function parseToken(string $token): ?array
        {
            $parts = explode(':', $token);
            return count($parts) === 2 ? $parts : null;
        }

        /**
         * Stores a token in the database with its expiration set.
         *
         * @param User $user The associated user.
         * @param string $type The token type.
         * @param string $selector Token selector for quick lookup.
         * @param string $validator Hashed validator for security.
         * @param int $seconds Token lifespan in seconds.
         * @return bool True if stored successfully.
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
         * Validates the authenticity and expiration of a token.
         *
         * @param string $token The token to validate.
         * @return bool True if valid and active, otherwise false.
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
         * Deletes all tokens for a user.
         *
         * @param User $user The user whose tokens are to be deleted.
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
         * Lists all tokens for a user.
         *
         * @param User $user The user in question.
         * @return Token[] Array of tokens.
         */
        public function listAllTokensForUser(User $user): array
        {
            return $user->getTokens()->toArray();
        }

        /**
         * Checks if a token has expired.
         *
         * @param DateTime $expiryDate The expiry date of the token.
         * @return bool True if expired, otherwise false.
         */
        private function hasTokenExpired(DateTime $expiryDate): bool
        {
            return $expiryDate < new DateTime();
        }

        /**
         * Automatically removes expired tokens from the database.
         *
         * @return int Number of expired tokens deleted.
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
    }
}
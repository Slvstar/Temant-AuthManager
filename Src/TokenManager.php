<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTime;
    use Doctrine\DBAL\Types\Types;
    use Doctrine\ORM\EntityManagerInterface;
    use stdClass;
    use Stringable;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;

    /**
     * Manages authentication tokens for users.
     */
    class TokenManager
    {
        /**
         * @var int Specifies the bcrypt hash cost for token validation.
         */
        public const VALIDATOR_HASH_COST = 12;

        /**
         * Constructor to initialize the TokenManager.
         *
         * @param EntityManagerInterface $entityManager Handles database operations for tokens.
         */
        public function __construct(private EntityManagerInterface $entityManager)
        {
            $this->cleanupExpiredTokens();
        }

        /**
         * Generates a secure authentication token.
         *
         * @return TokenDto Contains the selector, hashed validator, and the full token string.
         */
        public function generateToken(): TokenDto
        {
            $selector = bin2hex(random_bytes(16)); // 16 bytes selector
            $plainValidator = bin2hex(random_bytes(32)); // 32 bytes plaintext validator
            $hashedValidator = password_hash($plainValidator, PASSWORD_DEFAULT, ['cost' => self::VALIDATOR_HASH_COST]); // Hash the validator

            // Return a TokenRepresentation object with all the necessary fields
            return new TokenDto($selector, $hashedValidator, $plainValidator);
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
         * Parses a token string into selector and plain validator components.
         *
         * @param string $token The full token string.
         * @return string[]|null Selector and plain validator if valid, otherwise null.
         */
        public function parseToken(string $token): ?array
        {
            $parts = explode(':', $token);
            return count($parts) === 2 ? $parts : null;
        }

        /**
         * Saves a token for a user in the database.
         *
         * @param User $user The user to associate with the token.
         * @param string $type Token type (e.g., 'password_reset', 'email_activation').
         * @param string $selector The selector part of the token.
         * @param string $hashedValidator The hashed validator part of the token.
         * @param int $lifetime Token validity duration in seconds.
         * @return bool True if the token is saved successfully.
         */
        public function saveToken(User $user, string $type, string $selector, string $hashedValidator, int $lifetime): bool
        {
            $token = (new Token())
                ->setUser($user)
                ->setType($type)
                ->setSelector($selector)
                ->setValidator($hashedValidator)
                ->setExpiresAt((new DateTime())->modify("+$lifetime seconds"));

            $this->entityManager->persist($token);
            $this->entityManager->flush();

            return $this->entityManager->contains($token);
        }

        /**
         * Retrieves a token entity by its selector.
         *
         * @param string $selector The token selector.
         * @return Token|null The token entity if found, or null if not.
         */
        public function getTokenBySelector(string $selector): ?Token
        {
            return $this->entityManager->getRepository(Token::class)->findOneBy(['selector' => $selector]);
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


            // Ensure the token exists and has not expired
            if (!$tokenData || $this->hasTokenExpired($tokenData->getExpiresAt())) {
                return false;
            }

            // Verify the validator part of the token
            return password_verify($validator, $tokenData->getValidator());
        }

        /**
         * Deletes a token from the database.
         *
         * @param Token $token The token to remove.
         */
        public function removeToken(Token $token): void
        {
            $this->entityManager->remove($token);
            $this->entityManager->flush();
        }

        /**
         * Cleans up expired tokens from the database.
         *
         * @return int The number of tokens removed.
         */
        private function cleanupExpiredTokens(): int
        {
            return $this->entityManager
                ->createQueryBuilder()
                ->delete(Token::class, 't')
                ->where('t.expiresAt < :now')
                ->setParameter('now', new DateTime(), Types::DATETIME_MUTABLE)
                ->getQuery()
                ->execute();
        }

        /**
         * Checks whether a token has expired.
         *
         * @param DateTime $expiresAt The expiration date of the token.
         * @return bool True if the token has expired, false otherwise.
         */
        private function hasTokenExpired(DateTime $expiresAt): bool
        {
            return $expiresAt < new DateTime();
        }
    }

    /**
     * Represents a secure token with both selector and validator.
     */
    final readonly class TokenDto
    {
        public string $token;

        public function __construct(
            public string $selector,
            public string $hashedValidator,
            public string $plainValidator
        ) {
            $this->token = sprintf("%s:%s", $this->selector, $this->plainValidator);
        }
    }
}
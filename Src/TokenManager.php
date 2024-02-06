<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateInterval;
    use DateTime;
    use Doctrine\DBAL\Types\Types;
    use Doctrine\ORM\EntityManagerInterface;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Repository\TokenRepository;

    /**
     * Manages authentication tokens throughout their lifecycle, including creation, storage, retrieval, validation, and deletion.
     * This class leverages Doctrine's EntityManager for interaction with the database, allowing for object-oriented data management
     * and abstracting direct database access. It supports various token-related operations essential for secure authentication
     * and session management within applications.
     */
    class TokenManager implements TokenManagerInterface
    {
        private TokenRepository $tokenRepository;

        /**
         * Initializes the TokenManager with Doctrine's EntityManager for database operations.
         *
         * @param EntityManagerInterface $entityManager EntityManager instance for managing token entities.
         */
        public function __construct(
            private EntityManagerInterface $entityManager
        ) {
            $this->tokenRepository = $this->entityManager->getRepository(Token::class);
        }

        /**
         * Generates a secure, unique authentication token,
         * consisting of a selector for identification and a hashed validator for verification.
         *
         * @return string[] An array containing the selector, hashed validator, and the full token string.
         */
        public static function generateToken(): array
        {
            // Unique identifier for database lookup.
            $selector = bin2hex(random_bytes(16));
            // Random string for validation.
            $validator = bin2hex(random_bytes(32));
            // Securely hashed validator.
            $hashedValidator = password_hash($validator, PASSWORD_DEFAULT);
            return [$selector, $hashedValidator, "$selector:" . $validator];
        }

        /**
         * Decomposes a token into its constituent selector and validator components.
         *
         * @param string $token The complete token string to be dissected.
         * @return string[]|null An array containing the selector and validator, or null if the format is incorrect.
         */
        public static function parseToken(string $token): ?array
        {
            $parts = explode(':', $token);
            return count($parts) === 2 ? $parts : null; // Validates token format.
        }

        /**
         * Stores a token in the database along with associated user information and expiration details.
         *
         * @param string $userId Identifier of the user associated with the token.
         * @param string $type Purpose of the token (e.g., 'session', 'reset').
         * @param string $selector Token's unique identifier for lookup.
         * @param string $validator Hashed validator part of the token for security.
         * @param int $days Lifespan of the token in days, defaults to 1 day.
         * @return bool Returns true upon successful storage, otherwise false.
         */
        public function saveToken(string $userId, string $type, string $selector, string $validator, int $days = 1): bool
        {
            return $this->tokenRepository->saveToken(
                (new Token())
                    ->setUserId($userId)
                    ->setType($type)
                    ->setSelector($selector)
                    ->setValidator($validator)
                    ->setExpiresAt((new DateTime())->add(new DateInterval('P' . $days . 'D')))
            );
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
         * @return string[]|null Returns token data if found and valid, otherwise null.
         */
        public function getTokenBySelector(string $selector): ?array
        {
            $token = $this->entityManager
                ->getRepository(Token::class)
                ->findOneBy(['selector' => $selector]);

            if ($token) {
                return [
                    'selector' => $token->getSelector(),
                    'validator' => $token->getValidator()
                ];
            }
            return null;
        }

        /**
         * Validates a token by matching the provided validator against the stored hashed validator.
         *
         * @param string $token The token to validate.
         * @return bool Returns true if the token is valid, otherwise false.
         */
        public function isValid(string $token): bool
        {
            [$selector, $validator] = self::parseToken($token) ?: ['', ''];
            $tokenData = $this->getTokenBySelector($selector);
            return isset($tokenData['validator']) && password_verify($validator, $tokenData['validator']);
        }

        public function listExpiredTokens(): ?Token
        {


            dump($this->tokenRepository->findExpiredTokens());

            $token = (new Token())
                ->setUserId('$userId')
                ->setType('$type')
                ->setSelector('$selector')
                ->setValidator('$validator')
                ->setExpiresAt((new DateTime())->add(new DateInterval('P' . 1 . 'D')));

            dump($this->tokenRepository->findBySelector('1111'));
            dump($this->tokenRepository->findByUser('Emad.A'));
            dump($this->tokenRepository->findByType('remember_me'));
            dump($this->tokenRepository->findByUserAndType('Emad.A', 'remember_me'));
            dd($this->tokenRepository->saveToken($token));


            return null;
        }

        /**
         * Deletes all tokens associated with a specific user ID, commonly used for logging out or account deactivation.
         *
         * @param string $userId User ID whose tokens are to be deleted.
         * @return int Number of tokens deleted.
         */
        public function removeAllTokensForUser(string $userId): int
        {
            return $this->entityManager
                ->createQueryBuilder()
                ->delete(Token::class, 't')
                ->where('t.userId = :userId')
                ->setParameter('userId', $userId)
                ->getQuery()
                ->execute();
        }

        /**
         * List all tokens associated with a specific user ID.
         *
         * @param string $userId User ID whose tokens are to be listed.
         * @return Token[] A list of tokens or empty array
         */
        public function listAllTokensForUser(string $userId): array
        {
            return $this->entityManager
                ->createQueryBuilder()
                ->select('t')
                ->from(Token::class, 't')
                ->where('t.userId = :userId')
                ->setParameter('userId', $userId)
                ->getQuery()
                ->execute();
        }

        /**
         * Determines if a token is expired based on its stored expiry date.
         *
         * @param string $expiryDate Token's expiry date in 'Y-m-d H:i:s' format.
         * @return bool Returns true if the token is expired, otherwise false.
         */
        public static function isTokenExpired(string $expiryDate): bool
        {
            return strtotime($expiryDate) < time();
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
<?php declare(strict_types=1);

namespace Temant\AuthManager\Repository {
    use DateTime;
    use Doctrine\ORM\EntityRepository;
    use Temant\AuthManager\Entity\Token;

    class TokenRepository extends EntityRepository
    {
        /**
         * Finds tokens by their type.
         *
         * @param string $type The type of tokens to find.
         * @return Token[] An array of Token entities of the specified type.
         */
        public function findByType(string $type): array
        {
            return $this->findBy(['type' => $type]);
        }

        /**
         * Finds tokens for a specific user.
         *
         * @param string $userId The ID of the user whose tokens to find.
         * @return Token[] An array of Token entities for the given user.
         */
        public function findByUser(string $userId): array
        {
            return $this->findBy(['userId' => $userId]);
        }

        /**
         * Finds tokens for a specific user and type.
         *
         * @param string $userId The ID of the user.
         * @param string $type The type of tokens to find.
         * @return Token[] An array of Token entities for the given user and type.
         */
        public function findByUserAndType(string $userId, string $type): array
        {
            return $this->findBy([
                'userId' => $userId,
                'type' => $type
            ]);
        }

        /**
         * Finds a token by its selector.
         *
         * @param string $selector The selector of the token to find.
         * @return Token|null A Token entity if found, null otherwise.
         */
        public function findBySelector(string $selector): ?Token
        {
            return $this->findOneBy(['selector' => $selector]);
        }

        /**
         * Lists all expired tokens.
         *
         * @return Token[] An array of Token entities that have expired.
         */
        public function findExpiredTokens(): array
        {
            return $this->createQueryBuilder('t')
                ->where('t.expiresAt < :now')
                ->setParameter('now', new DateTime())
                ->getQuery()->getResult();
        }

        /**
         * Deletes a token by its ID and returns success status.
         *
         * @param int $tokenId The ID of the token to delete.
         * @return bool True on successful deletion, false otherwise.
         */
        public function deleteTokenById(int $tokenId): bool
        {
            $token = $this->find($tokenId);
            if ($token) {
                $this->getEntityManager()->remove($token);
                $this->getEntityManager()->flush();
                return true;
            }
            return false;
        }

        /**
         * Deletes a specific token by its selector.
         *
         * @param string $selector The selector of the token to delete.
         */
        public function deleteTokenBySelector(string $selector): void
        {
            $token = $this->findTokenBySelector($selector);
            if ($token) {
                $this->getEntityManager()->remove($token);
                $this->getEntityManager()->flush();
            }
        }

        /**
         * Deletes all tokens for a specific user.
         *
         * @param string $userId The user ID whose tokens should be deleted.
         */
        public function deleteTokensForUser(string $userId): void
        {
            $tokens = $this->findBy(['userId' => $userId]);
            foreach ($tokens as $token) {
                $this->getEntityManager()->remove($token);
            }
            $this->getEntityManager()->flush();
        }

        /**
         * Deletes tokens by type and returns the number of tokens deleted.
         *
         * @param string $type The type of tokens to delete.
         * @return int The number of tokens deleted.
         */
        public function deleteTokensByType(string $type): int
        {
            $tokens = $this->findByType($type);
            foreach ($tokens as $token) {
                $this->getEntityManager()->remove($token);
            }
            $this->getEntityManager()->flush();

            return count($tokens);
        }

        /**
         * Deletes tokens for a specific user and type and returns the number of tokens deleted.
         *
         * @param string $userId The ID of the user.
         * @param string $type The type of tokens to delete.
         * @return int The number of tokens deleted.
         */
        public function deleteTokensByUserAndType(string $userId, string $type): int
        {
            $tokens = $this->findByUserAndType($userId, $type);
            foreach ($tokens as $token) {
                $this->getEntityManager()->remove($token);
            }
            $this->getEntityManager()->flush();

            return count($tokens);
        }

        /**
         * Saves a new token or updates an existing one in the database.
         *
         * @param Token $token The Token entity to save or update.
         */
        public function saveToken(Token $token): void
        {
            $this->getEntityManager()->persist($token);
            $this->getEntityManager()->flush();
        }

        /**
         * Deletes all expired tokens to clean up the database.
         */
        public function cleanupExpiredTokens(): void
        {
            $expiredTokens = $this->listExpiredTokens();
            foreach ($expiredTokens as $token) {
                $this->getEntityManager()->remove($token);
            }
            $this->getEntityManager()->flush();
        }
    }
}

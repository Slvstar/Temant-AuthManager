<?php declare(strict_types=1);

namespace Temant\AuthManager\Repository {
    use DateTimeImmutable;
    use Doctrine\Common\Collections\ArrayCollection;
    use Doctrine\ORM\EntityRepository;
    use Temant\AuthManager\Entity\AuthenticationAttempt;

    class AuthenticationAttemptRepository extends EntityRepository
    {
        public function countFailedAuthenticationAttempts(string $userId, int $timePeriod): int
        {
            $qb = $this->createQueryBuilder('a');
            $qb->select('count(a.id)')
                ->where('a.userId = :userId')
                ->andWhere('a.success = :success')
                ->andWhere('a.timestamp > :startTime')
                ->setParameters(new ArrayCollection([
                    'userId' => $userId,
                    'success' => false,
                    'startTime' => new DateTimeImmutable(sprintf('-%d seconds', $timePeriod))
                ]));

            return (int) $qb->getQuery()->getSingleScalarResult();
        }

        public function deleteAuthenticationAttempts(string $userId): bool
        {
            $qb = $this->createQueryBuilder('a');
            $qb->delete()
                ->where('a.userId = :userId')
                ->setParameter('userId', $userId);

            return (bool) $qb->getQuery()->execute();
        }

        public function getLastAuthenticationStatus(string $userId): ?bool
        {
            $qb = $this->createQueryBuilder('a');
            $qb->select('a.success')
                ->where('a.userId = :userId')
                ->orderBy('a.timestamp', 'DESC')
                ->setMaxResults(1)
                ->setParameter('userId', $userId);

            $result = $qb->getQuery()->getOneOrNullResult();
            return $result ? (bool) $result['success'] : null;
        }

        public function listAuthenticationAttempts(string $userId): array
        {
            return $this->findBy(['userId' => $userId], ['timestamp' => 'DESC']);
        }

        public function logAuthenticationAttempt(string $userId, bool $success, ?string $reason, ?string $ipAddress, ?string $userAgent): bool
        {
            $em = $this->getEntityManager();
            $attempt = new AuthenticationAttempt();
            $attempt->setUserId($userId)
                ->setSuccess($success)
                ->setReason($reason)
                ->setIpAddress($ipAddress)
                ->setUserAgent($userAgent)
                ->setTimestamp(new DateTimeImmutable());

            $em->persist($attempt);
            $em->flush();

            return true;
        }
    }

}
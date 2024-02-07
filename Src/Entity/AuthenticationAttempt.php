<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {
    use DateTime;
    use DateTimeInterface;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: "authentication_attempts")]
    class AuthenticationAttempt
    {
        #[Id]
        #[GeneratedValue]
        #[Column]
        private ?int $id = null;

        #[Column(name: "user_id")]
        private int $userId;

        #[Column]
        private bool $success;

        #[Column]
        private ?string $reason = null;

        #[Column(name: "ip_address")]
        private string $ipAddress;

        #[Column(name: "user_agent")]
        private ?string $userAgent = null;

        #[Column(name: "created_at", type: "datetime")]
        private DateTimeInterface $createdAt;

        public function __construct()
        {
            $this->createdAt = new DateTime();
        }

        public function getId(): ?int
        {
            return $this->id;
        }

        public function getUserId(): int
        {
            return $this->userId;
        }

        public function setUserId(int $userId): self
        {
            $this->userId = $userId;
            return $this;
        }

        public function getSuccess(): bool
        {
            return $this->success;
        }

        public function setSuccess(bool $success): self
        {
            $this->success = $success;
            return $this;
        }

        public function getReason(): ?string
        {
            return $this->reason;
        }

        public function setReason(?string $reason): self
        {
            $this->reason = $reason;
            return $this;
        }

        public function getIpAddress(): string
        {
            return $this->ipAddress;
        }

        public function setIpAddress(string $ipAddress): self
        {
            $this->ipAddress = $ipAddress;
            return $this;
        }

        public function getUserAgent(): ?string
        {
            return $this->userAgent;
        }

        public function setUserAgent(?string $userAgent): self
        {
            $this->userAgent = $userAgent;
            return $this;
        }

        public function getCreatedAt(): DateTimeInterface
        {
            return $this->createdAt;
        }

        public function setCreatedAt(DateTimeInterface $createdAt): self
        {
            $this->createdAt = $createdAt;
            return $this;
        }
    }
}
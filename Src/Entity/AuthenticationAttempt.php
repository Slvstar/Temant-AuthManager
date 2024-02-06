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
        private string $userId;

        #[Column]
        private bool $success;

        #[Column]
        private ?string $reason = null;

        #[Column(name: "ip_address")]
        private string $ipAddress;

        #[Column(name: "user_agent")]
        private ?string $userAgent = null;

        #[Column(type: "datetime")]
        private DateTimeInterface $timestamp;

        public function __construct()
        {
            $this->timestamp = new DateTime();
        }

        public function getId(): ?int
        {
            return $this->id;
        }

        public function getUserId(): string
        {
            return $this->userId;
        }

        public function setUserId(string $userId): self
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

        public function getTimestamp(): DateTimeInterface
        {
            return $this->timestamp;
        }

        public function setTimestamp(DateTimeInterface $timestamp): self
        {
            $this->timestamp = $timestamp;
            return $this;
        }
    }
}
<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {

    use DateTime;
    use DateTimeInterface;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\JoinColumn;
    use Doctrine\ORM\Mapping\ManyToOne;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: "authentication_attempts")]
    class AttemptEntity
    {
        #[Id]
        #[GeneratedValue]
        #[Column]
        private ?int $id = null;

        #[ManyToOne(targetEntity: UserEntity::class, inversedBy: 'attempts')]
        #[JoinColumn(name: "user_id", referencedColumnName: "id", nullable: false, onDelete: "CASCADE")]
        private UserEntity $user;

        #[Column]
        private bool $success;

        #[Column(nullable: true)]
        private ?string $reason = null;

        #[Column(name: "ip_address")]
        private string $ipAddress;

        #[Column(name: "user_agent")]
        private ?string $userAgent = null;

        #[Column(name: "location", nullable: true)]
        private ?string $location = null;

        #[Column(name: "device_type", nullable: true)]
        private ?string $deviceType = null;

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

        public function getLocation(): ?string
        {
            return $this->location;
        }

        public function setLocation(?string $location): self
        {
            $this->location = $location;
            return $this;
        }

        public function getDeviceType(): ?string
        {
            return $this->deviceType;
        }

        public function setDeviceType(?string $deviceType): self
        {
            $this->deviceType = $deviceType;
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

        public function getUser(): UserEntity
        {
            return $this->user;
        }

        public function setUser(UserEntity $user): self
        {
            $this->user = $user;
            return $this;
        }
    }
}
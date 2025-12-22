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
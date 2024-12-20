<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {

    use DateTime;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\JoinColumn;
    use Doctrine\ORM\Mapping\ManyToOne;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: "authentication_tokens")]
    class TokenEntity
    {
        #[Id]
        #[GeneratedValue]
        #[Column(type: "integer")]
        private int $id;

        #[ManyToOne(targetEntity: UserEntity::class, inversedBy: 'tokens')]
        #[JoinColumn(name: "user_id", referencedColumnName: "id", nullable: false, onDelete: "CASCADE")]
        private UserEntity $user;

        #[Column(type: "string", length: 32)]
        private string $selector;

        #[Column(type: "text")]
        private string $validator;

        #[Column(type: "string", length: 255)]
        private string $type;

        #[Column(name: "expires_at", type: "datetime")]
        private ?DateTime $expiresAt;

        #[Column(name: "created_at", type: "datetime")]
        private DateTime $createdAt;

        public function __construct()
        {
            $this->createdAt = new DateTime();
        }

        public function getId(): int
        {
            return $this->id;
        }

        public function getSelector(): string
        {
            return $this->selector;
        }

        public function setSelector(string $selector): self
        {
            $this->selector = $selector;
            return $this;
        }

        public function getValidator(): string
        {
            return $this->validator;
        }

        public function setValidator(string $validator): self
        {
            $this->validator = $validator;
            return $this;
        }

        public function getType(): string
        {
            return $this->type;
        }

        public function setType(string $type): self
        {
            $this->type = $type;
            return $this;
        }

        public function getExpiresAt(): ?DateTime
        {
            return $this->expiresAt;
        }

        public function setExpiresAt(?DateTime $expiresAt): self
        {
            $this->expiresAt = $expiresAt;
            return $this;
        }

        public function getCreatedAt(): DateTime
        {
            return $this->createdAt;
        }

        public function setCreatedAt(DateTime $createdAt): self
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
            $user->addToken($this);
            return $this;
        }

        public function isValid(): bool
        {
            return $this->expiresAt === null || new DateTime() < $this->expiresAt;
        }

        public function isExpired(): bool
        {
            return $this->expiresAt !== null && new DateTime() > $this->expiresAt;
        }
    }
}
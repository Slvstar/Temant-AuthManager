<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {
    use DateTime;
    use DateTimeInterface;
    use Doctrine\Common\Collections\ArrayCollection;
    use Doctrine\Common\Collections\Collection;
    use Doctrine\DBAL\Types\Types;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\ManyToOne;
    use Doctrine\ORM\Mapping\OneToMany;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: 'authentication_users')]
    class User
    {
        #[Id]
        #[GeneratedValue]
        #[Column(name: 'id')]
        private int $id;

        #[Column(name: 'username')]
        private string $username;

        #[Column(name: 'first_name')]
        private string $firstName;

        #[Column(name: 'last_name')]
        private string $lastName;

        #[Column(name: 'email')]
        private string $email;

        #[Column(name: 'password')]
        private string $password;

        #[Column(name: 'is_activated', type: Types::BOOLEAN)]
        private bool $isActivated;

        #[Column(name: 'is_locked')]
        private bool $isLocked;

        #[Column(name: 'created_at', type: "datetime")]
        private DateTimeInterface $createdAt;

        #[ManyToOne(targetEntity: Role::class, inversedBy: "users")]
        private ?Role $role = null;

        #[OneToMany(targetEntity: Token::class, mappedBy: "user", cascade: ["persist", "remove"])]
        private Collection $tokens;

        #[OneToMany(targetEntity: Attempt::class, mappedBy: "user", cascade: ["persist", "remove"])]
        private Collection $attempts;

        public function __construct()
        {
            $this->createdAt = new DateTime();
            $this->tokens = new ArrayCollection;
            $this->attempts = new ArrayCollection;
        }

        public function getId(): int
        {
            return $this->id;
        }

        public function getUserName(): string
        {
            return $this->username;
        }

        public function setUserName(string $username): self
        {
            $this->username = $username;
            return $this;
        }

        public function getFirstName(): string
        {
            return $this->firstName;
        }

        public function setFirstName(string $firstName): self
        {
            $this->firstName = $firstName;
            return $this;
        }

        public function getLastName(): string
        {
            return $this->lastName;
        }

        public function setLastName(string $lastName): self
        {
            $this->lastName = $lastName;
            return $this;
        }

        public function getFullName(): string
        {
            return sprintf("%s %s", $this->firstName, $this->lastName);
        }

        public function getEmail(): string
        {
            return $this->email;
        }

        public function setEmail(string $email): self
        {
            $this->email = $email;
            return $this;
        }

        public function getPassword(): string
        {
            return $this->password;
        }

        public function setPassword(string $password): self
        {
            $this->password = $password;
            return $this;
        }

        public function getIsActivated(): bool
        {
            return $this->isActivated;
        }

        public function setIsActivated(bool $isActivated): self
        {
            $this->isActivated = $isActivated;
            return $this;
        }

        public function getIsLocked(): bool
        {
            return $this->isLocked;
        }

        public function setIsLocked(bool $isLocked): self
        {
            $this->isLocked = $isLocked;
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

        public function getTokens(): Collection
        {
            return $this->tokens;
        }

        public function addToken(Token $token): self
        {
            if (!$this->tokens->contains($token)) {
                $this->tokens[] = $token;
                $token->setUser($this);
            }
            return $this;
        }

        public function removeToken(Token $token): bool
        {
            return $this->tokens->removeElement($token);
        }

        public function getAttempts(): Collection
        {
            return $this->attempts;
        }

        public function addAttempt(Attempt $attempt): self
        {
            if (!$this->attempts->contains($attempt)) {
                $this->attempts[] = $attempt;
                $attempt->setUser($this);
            }
            return $this;
        }

        public function removeAttempt(Attempt $attempt): bool
        {
            return $this->attempts->removeElement($attempt);
        }

        public function getRole(): ?Role
        {
            return $this->role;
        }

        public function setRole(?Role $role): self
        {
            $this->role = $role;
            return $this;
        }
    }
}
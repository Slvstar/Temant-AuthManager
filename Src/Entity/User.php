<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {
    use DateTime;
    use DateTimeInterface;
    use Doctrine\Common\Collections\ArrayCollection;
    use Doctrine\Common\Collections\Collection;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\OneToMany;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: 'authentication_users')]
    class User
    {
        #[Id]
        #[Column(name: 'user_id')]
        private string $userId;

        #[Column(name: 'first_name')]
        private string $firstName;

        #[Column(name: 'last_name')]
        private string $lastName;

        #[Column(name: 'email')]
        private string $email;

        #[Column(name: 'password')]
        private string $password;

        #[Column(name: 'is_activated')]
        private bool $isActivated;

        #[Column(name: 'is_locked')]
        private bool $isLocked;

        #[Column(name: 'created_at', type: "datetime")]
        private DateTimeInterface $createdAt;

        #[OneToMany(targetEntity: Token::class, mappedBy: "user", cascade: ["all"])]
        private Collection $tokens;

        public function __construct()
        {
            $this->createdAt = new DateTime();
            $this->tokens = new ArrayCollection;
        }

        /**
         * @return string
         */
        public function getUserId(): string
        {
            return $this->userId;
        }

        /**
         * @param string $userId 
         * @return self
         */
        public function setUserId(string $userId): self
        {
            $this->userId = $userId;
            return $this;
        }

        /**
         * @return string
         */
        public function getFirstName(): string
        {
            return $this->firstName;
        }

        /**
         * @param string $firstName 
         * @return self
         */
        public function setFirstName(string $firstName): self
        {
            $this->firstName = $firstName;
            return $this;
        }

        /**
         * @return string
         */
        public function getLastName(): string
        {
            return $this->lastName;
        }

        /**
         * @param string $lastName 
         * @return self
         */
        public function setLastName(string $lastName): self
        {
            $this->lastName = $lastName;
            return $this;
        }

        /**
         * @return string
         */
        public function getEmail(): string
        {
            return $this->email;
        }

        /**
         * @param string $email 
         * @return self
         */
        public function setEmail(string $email): self
        {
            $this->email = $email;
            return $this;
        }

        /**
         * @return string
         */
        public function getPassword(): string
        {
            return $this->password;
        }

        /**
         * @param string $password 
         * @return self
         */
        public function setPassword(string $password): self
        {
            $this->password = $password;
            return $this;
        }

        /**
         * @return bool
         */
        public function getIsActivated(): bool
        {
            return $this->isActivated;
        }

        /**
         * @param bool $isActivated 
         * @return self
         */
        public function setIsActivated(bool $isActivated): self
        {
            $this->isActivated = $isActivated;
            return $this;
        }

        /**
         * @return bool
         */
        public function getIsLocked(): bool
        {
            return $this->isLocked;
        }

        /**
         * @param bool $isLocked 
         * @return self
         */
        public function setIsLocked(bool $isLocked): self
        {
            $this->isLocked = $isLocked;
            return $this;
        }

        /**
         * @return DateTimeInterface
         */
        public function getCreatedAt(): DateTimeInterface
        {
            return $this->createdAt;
        }

        /**
         * @param DateTimeInterface $createdAt 
         * @return self
         */
        public function setCreatedAt(DateTimeInterface $createdAt): self
        {
            $this->createdAt = $createdAt;
            return $this;
        }

        /**
         * @return Collection
         */
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
    }
}
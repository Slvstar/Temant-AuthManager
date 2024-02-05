<?php

namespace Temant\AuthManager\Entity {

    use DateTime;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: "auth_token")]
    class TokenEntity
    {
        #[Id]
        #[GeneratedValue]
        #[Column(type: "integer")]
        private int $id;

        #[Column(name: "user_id", type: "string", length: 255, nullable: true)]
        private ?string $userId;

        #[Column(type: "string", length: 32, nullable: true)]
        private ?string $selector;

        #[Column(type: "text", nullable: true)]
        private ?string $validator;

        #[Column(type: "string", length: 255, nullable: true)]
        private ?string $type;

        #[Column(name: "expires_at", type: "datetime", nullable: true)]
        private ?DateTime $expiresAt;

        #[Column(name: "created_at", type: "datetime")]
        private DateTime $createdAt;

        public function __construct()
        {
            $this->createdAt = new DateTime();
        }

        /**
         * @return int
         */
        public function getId(): int
        {
            return $this->id;
        }

        /**
         * @param int $id 
         * @return self
         */
        public function setId(int $id): self
        {
            $this->id = $id;
            return $this;
        }

        /**
         * @return 
         */
        public function getUserId(): ?string
        {
            return $this->userId;
        }

        /**
         * @param  $userId 
         * @return self
         */
        public function setUserId(?string $userId): self
        {
            $this->userId = $userId;
            return $this;
        }

        /**
         * @return 
         */
        public function getSelector(): ?string
        {
            return $this->selector;
        }

        /**
         * @param  $selector 
         * @return self
         */
        public function setSelector(?string $selector): self
        {
            $this->selector = $selector;
            return $this;
        }

        /**
         * @return 
         */
        public function getValidator(): ?string
        {
            return $this->validator;
        }

        /**
         * @param  $validator 
         * @return self
         */
        public function setValidator(?string $validator): self
        {
            $this->validator = $validator;
            return $this;
        }

        /**
         * @return 
         */
        public function getType(): ?string
        {
            return $this->type;
        }

        /**
         * @param  $type 
         * @return self
         */
        public function setType(?string $type): self
        {
            $this->type = $type;
            return $this;
        }

        /**
         * @return 
         */
        public function getExpiresAt(): ?DateTime
        {
            return $this->expiresAt;
        }

        /**
         * @param  $expiresAt 
         * @return self
         */
        public function setExpiresAt(?DateTime $expiresAt): self
        {
            $this->expiresAt = $expiresAt;
            return $this;
        }

        /**
         * @return DateTime
         */
        public function getCreatedAt(): DateTime
        {
            return $this->createdAt;
        }

        /**
         * @param DateTime $createdAt 
         * @return self
         */
        public function setCreatedAt(DateTime $createdAt): self
        {
            $this->createdAt = $createdAt;
            return $this;
        }
    }
}
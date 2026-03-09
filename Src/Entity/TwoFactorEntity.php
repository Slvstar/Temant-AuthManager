<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {

    use DateTime;
    use DateTimeInterface;
    use Doctrine\DBAL\Types\Types;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\JoinColumn;
    use Doctrine\ORM\Mapping\OneToOne;
    use Doctrine\ORM\Mapping\Table;

    /**
     * Stores the TOTP secret and backup codes for a user's 2FA setup.
     *
     * The entity is created when the user initiates 2FA setup and is considered
     * active only after isEnabled=true AND isConfirmed=true.
     */
    #[Entity]
    #[Table(name: "authentication_two_factor")]
    class TwoFactorEntity
    {
        #[Id]
        #[GeneratedValue]
        #[Column(type: Types::INTEGER)]
        private int $id;

        #[OneToOne(targetEntity: UserEntity::class, inversedBy: 'twoFactor')]
        #[JoinColumn(name: "user_id", referencedColumnName: "id", nullable: false, onDelete: "CASCADE")]
        private UserEntity $user;

        /** Base32-encoded TOTP secret shared with the authenticator app. */
        #[Column(type: Types::STRING, length: 64)]
        private string $secret;

        /**
         * Indexed array of bcrypt-hashed backup codes.
         * The plaintext codes are shown once and never stored.
         *
         * @var array<int, string>
         */
        #[Column(type: Types::JSON)]
        private array $backupCodes = [];

        /** Whether 2FA is currently active for the user. */
        #[Column(type: Types::BOOLEAN, options: ["default" => false])]
        private bool $isEnabled = false;

        /**
         * Whether the user has successfully verified the first TOTP code after setup.
         * 2FA is only enforced once confirmed.
         */
        #[Column(type: Types::BOOLEAN, options: ["default" => false])]
        private bool $isConfirmed = false;

        #[Column(name: "created_at", type: Types::DATETIME_MUTABLE)]
        private DateTimeInterface $createdAt;

        #[Column(name: "enabled_at", type: Types::DATETIME_MUTABLE, nullable: true)]
        private ?DateTimeInterface $enabledAt = null;

        public function __construct()
        {
            $this->createdAt = new DateTime();
        }

        public function getId(): int
        {
            return $this->id;
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

        public function getSecret(): string
        {
            return $this->secret;
        }

        public function setSecret(string $secret): self
        {
            $this->secret = $secret;
            return $this;
        }

        /** @return array<int, string> */
        public function getBackupCodes(): array
        {
            return $this->backupCodes;
        }

        /** @param array<int, string> $backupCodes */
        public function setBackupCodes(array $backupCodes): self
        {
            $this->backupCodes = $backupCodes;
            return $this;
        }

        public function isEnabled(): bool
        {
            return $this->isEnabled;
        }

        public function setIsEnabled(bool $isEnabled): self
        {
            $this->isEnabled = $isEnabled;
            if ($isEnabled && $this->enabledAt === null) {
                $this->enabledAt = new DateTime();
            }
            return $this;
        }

        public function isConfirmed(): bool
        {
            return $this->isConfirmed;
        }

        public function setIsConfirmed(bool $isConfirmed): self
        {
            $this->isConfirmed = $isConfirmed;
            return $this;
        }

        public function getCreatedAt(): DateTimeInterface
        {
            return $this->createdAt;
        }

        public function getEnabledAt(): ?DateTimeInterface
        {
            return $this->enabledAt;
        }
    }
}

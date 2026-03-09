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
    use Doctrine\ORM\Mapping\HasLifecycleCallbacks;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\InverseJoinColumn;
    use Doctrine\ORM\Mapping\JoinColumn;
    use Doctrine\ORM\Mapping\JoinTable;
    use Doctrine\ORM\Mapping\ManyToMany;
    use Doctrine\ORM\Mapping\OneToMany;
    use Doctrine\ORM\Mapping\OneToOne;
    use Doctrine\ORM\Mapping\PrePersist;
    use Doctrine\ORM\Mapping\PreUpdate;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: 'authentication_users')]
    #[HasLifecycleCallbacks]
    class UserEntity
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

        #[Column(name: 'is_activated', type: Types::BOOLEAN, options: ["default" => true])]
        private bool $isActivated;

        #[Column(name: 'is_locked', type: Types::BOOLEAN, options: ["default" => false])]
        private bool $isLocked;

        #[Column(name: 'created_at', type: Types::DATETIME_MUTABLE, options: ["default" => "CURRENT_TIMESTAMP"])]
        private DateTimeInterface $createdAt;

        #[Column(name: 'updated_at', type: Types::DATETIME_MUTABLE, nullable: true)]
        private ?DateTimeInterface $updatedAt = null;

        #[Column(nullable: true)]
        private ?string $locale = null;

        // ── Roles (Many-to-Many) ──────────────────────────────────────────────
        // A user can hold multiple roles; permissions are resolved from all of them
        // plus any parent roles (hierarchical inheritance).

        #[ManyToMany(targetEntity: RoleEntity::class, inversedBy: "users")]
        #[JoinTable(name: "authentication_user_roles")]
        #[JoinColumn(name: "user_id", referencedColumnName: "id")]
        #[InverseJoinColumn(name: "role_id", referencedColumnName: "id")]
        private Collection $roles;

        // ── Direct permissions (Many-to-Many) ─────────────────────────────────
        // Fine-grained control: grant individual permissions without a role.

        #[ManyToMany(targetEntity: PermissionEntity::class)]
        #[JoinTable(name: "authentication_user_permissions")]
        #[JoinColumn(name: "user_id", referencedColumnName: "id")]
        #[InverseJoinColumn(name: "permission_id", referencedColumnName: "id")]
        private Collection $directPermissions;

        #[OneToMany(targetEntity: TokenEntity::class, mappedBy: "user", cascade: ["persist", "remove"], orphanRemoval: true)]
        private Collection $tokens;

        #[OneToMany(targetEntity: AttemptEntity::class, mappedBy: "user", cascade: ["persist", "remove"], orphanRemoval: true)]
        private Collection $attempts;

        #[OneToOne(targetEntity: ProfileEntity::class, mappedBy: "user", cascade: ["persist", "remove"], orphanRemoval: true)]
        private ?ProfileEntity $profile = null;

        #[OneToOne(targetEntity: TwoFactorEntity::class, mappedBy: "user", cascade: ["persist", "remove"], orphanRemoval: true)]
        private ?TwoFactorEntity $twoFactor = null;

        public function __construct()
        {
            $this->createdAt        = new DateTime();
            $this->tokens           = new ArrayCollection();
            $this->attempts         = new ArrayCollection();
            $this->roles            = new ArrayCollection();
            $this->directPermissions = new ArrayCollection();
        }

        // ── Identity ─────────────────────────────────────────────────────────

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
            return sprintf('%s %s', $this->firstName, $this->lastName);
        }

        public function getInitials(): string
        {
            return sprintf(
                '%s%s',
                strtoupper(substr($this->firstName, 0, 1)),
                strtoupper(substr($this->lastName, 0, 1))
            );
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

        // ── Account status ────────────────────────────────────────────────────

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

        // ── Timestamps ────────────────────────────────────────────────────────

        public function getCreatedAt(): DateTimeInterface
        {
            return $this->createdAt;
        }

        public function setCreatedAt(DateTimeInterface $createdAt): self
        {
            $this->createdAt = $createdAt;
            return $this;
        }

        public function getUpdatedAt(): ?DateTimeInterface
        {
            return $this->updatedAt;
        }

        public function setUpdatedAt(?DateTimeInterface $updatedAt): self
        {
            $this->updatedAt = $updatedAt;
            return $this;
        }

        #[PrePersist]
        #[PreUpdate]
        public function updateTimestamps(): void
        {
            $this->updatedAt = new DateTime();
            if (!isset($this->createdAt)) {
                $this->createdAt = new DateTime();
            }
        }

        // ── Locale ────────────────────────────────────────────────────────────

        public function getLocale(): ?string
        {
            return $this->locale;
        }

        public function setLocale(?string $locale): self
        {
            $this->locale = $locale;
            return $this;
        }

        // ── Roles ─────────────────────────────────────────────────────────────

        public function getRoles(): Collection
        {
            return $this->roles;
        }

        public function addRole(RoleEntity $role): self
        {
            if (!$this->roles->contains($role)) {
                $this->roles[] = $role;
            }
            return $this;
        }

        public function removeRole(RoleEntity $role): self
        {
            $this->roles->removeElement($role);
            return $this;
        }

        public function hasRole(string $roleName): bool
        {
            return $this->roles->exists(
                static fn($key, RoleEntity $role): bool => $role->getName() === $roleName
            );
        }

        // ── Permissions ───────────────────────────────────────────────────────

        public function getDirectPermissions(): Collection
        {
            return $this->directPermissions;
        }

        public function addDirectPermission(PermissionEntity $permission): self
        {
            if (!$this->directPermissions->contains($permission)) {
                $this->directPermissions[] = $permission;
            }
            return $this;
        }

        public function removeDirectPermission(PermissionEntity $permission): self
        {
            $this->directPermissions->removeElement($permission);
            return $this;
        }

        /**
         * Returns the deduplicated union of:
         *   • direct permissions assigned to this user, and
         *   • permissions from every assigned role (recursively through parent roles).
         *
         * @return PermissionEntity[]
         */
        public function listPermissions(): array
        {
            /** @var array<string, PermissionEntity> $map */
            $map = [];

            foreach ($this->directPermissions as $permission) {
                $map[$permission->getName()] = $permission;
            }

            foreach ($this->roles as $role) {
                foreach ($this->collectRolePermissions($role) as $permission) {
                    $map[$permission->getName()] = $permission;
                }
            }

            return array_values($map);
        }

        /**
         * Returns true when the user holds the named permission either directly
         * or via any assigned role (including inherited parent-role permissions).
         */
        public function hasPermission(string $permissionName): bool
        {
            // Direct check
            foreach ($this->directPermissions as $permission) {
                if ($permission->getName() === $permissionName) {
                    return true;
                }
            }

            // Role-based check (with hierarchy)
            foreach ($this->roles as $role) {
                foreach ($this->collectRolePermissions($role) as $permission) {
                    if ($permission->getName() === $permissionName) {
                        return true;
                    }
                }
            }

            return false;
        }

        /** Recursively gathers all permissions from a role and its ancestor chain. */
        private function collectRolePermissions(RoleEntity $role): array
        {
            $permissions = $role->getPermissions()->toArray();
            $parent      = $role->getParent();
            if ($parent !== null) {
                $permissions = array_merge($permissions, $this->collectRolePermissions($parent));
            }
            return $permissions;
        }

        // ── Two-factor authentication ─────────────────────────────────────────

        public function getTwoFactor(): ?TwoFactorEntity
        {
            return $this->twoFactor;
        }

        public function setTwoFactor(?TwoFactorEntity $twoFactor): self
        {
            $this->twoFactor = $twoFactor;
            return $this;
        }

        /** Returns true only when 2FA has been set up, enabled, AND confirmed. */
        public function isTwoFactorEnabled(): bool
        {
            return $this->twoFactor !== null
                && $this->twoFactor->isEnabled()
                && $this->twoFactor->isConfirmed();
        }

        // ── Tokens ────────────────────────────────────────────────────────────

        public function getTokens(): Collection
        {
            return $this->tokens;
        }

        public function addToken(TokenEntity $token): self
        {
            if (!$this->tokens->contains($token)) {
                $this->tokens[] = $token;
                $token->setUser($this);
            }
            return $this;
        }

        public function removeToken(TokenEntity $token): bool
        {
            return $this->tokens->removeElement($token);
        }

        // ── Attempts ─────────────────────────────────────────────────────────

        public function getAttempts(): Collection
        {
            return $this->attempts;
        }

        public function addAttempt(AttemptEntity $attempt): self
        {
            if (!$this->attempts->contains($attempt)) {
                $this->attempts[] = $attempt;
                $attempt->setUser($this);
            }
            return $this;
        }

        public function removeAttempt(AttemptEntity $attempt): bool
        {
            return $this->attempts->removeElement($attempt);
        }

        // ── Profile ───────────────────────────────────────────────────────────

        public function getProfile(): ?ProfileEntity
        {
            return $this->profile;
        }

        public function setProfile(?ProfileEntity $profile): self
        {
            if ($profile === null && $this->profile !== null) {
                $this->profile->setUser(null);
            }
            if ($profile !== null && $profile->getUser() !== $this) {
                $profile->setUser($this);
            }
            $this->profile = $profile;
            return $this;
        }
    }
}

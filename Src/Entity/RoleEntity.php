<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {

    use Doctrine\Common\Collections\ArrayCollection;
    use Doctrine\Common\Collections\Collection;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\InverseJoinColumn;
    use Doctrine\ORM\Mapping\JoinColumn;
    use Doctrine\ORM\Mapping\JoinTable;
    use Doctrine\ORM\Mapping\ManyToMany;
    use Doctrine\ORM\Mapping\ManyToOne;
    use Doctrine\ORM\Mapping\OneToMany;
    use Doctrine\ORM\Mapping\Table;

    /**
     * Represents a named role that can be assigned to users.
     *
     * Roles form an optional hierarchy: a role can inherit all permissions from
     * its parent role.  Circular hierarchies are not enforced at the ORM level
     * and should be avoided in application logic.
     */
    #[Entity]
    #[Table(name: "authentication_roles")]
    class RoleEntity
    {
        #[Id]
        #[Column]
        #[GeneratedValue]
        private int $id;

        #[Column(unique: true)]
        private string $name;

        #[Column(nullable: true)]
        private ?string $description = null;

        // ── Role hierarchy ────────────────────────────────────────────────────

        /** Parent role — this role inherits all of the parent's permissions. */
        #[ManyToOne(targetEntity: self::class, inversedBy: "children")]
        #[JoinColumn(name: "parent_id", referencedColumnName: "id", nullable: true, onDelete: "SET NULL")]
        private ?RoleEntity $parent = null;

        #[OneToMany(targetEntity: self::class, mappedBy: "parent")]
        private Collection $children;

        // ── Relationships ─────────────────────────────────────────────────────

        /** Inverse side of the User ↔ Role Many-to-Many. */
        #[ManyToMany(targetEntity: UserEntity::class, mappedBy: "roles")]
        private Collection $users;

        #[ManyToMany(targetEntity: PermissionEntity::class, inversedBy: "roles")]
        #[JoinTable(name: "authentication_role_permissions")]
        #[JoinColumn(name: 'role_id', referencedColumnName: 'id')]
        #[InverseJoinColumn(name: 'permission_id', referencedColumnName: 'id')]
        private Collection $permissions;

        public function __construct()
        {
            $this->permissions = new ArrayCollection();
            $this->users       = new ArrayCollection();
            $this->children    = new ArrayCollection();
        }

        // ── Getters / Setters ─────────────────────────────────────────────────

        public function getId(): int
        {
            return $this->id;
        }

        public function getName(): string
        {
            return $this->name;
        }

        public function setName(string $name): self
        {
            $this->name = $name;
            return $this;
        }

        public function getDescription(): ?string
        {
            return $this->description;
        }

        public function setDescription(?string $description): self
        {
            $this->description = $description;
            return $this;
        }

        // ── Hierarchy ─────────────────────────────────────────────────────────

        public function getParent(): ?RoleEntity
        {
            return $this->parent;
        }

        public function setParent(?RoleEntity $parent): self
        {
            $this->parent = $parent;
            return $this;
        }

        public function getChildren(): Collection
        {
            return $this->children;
        }

        // ── Users ─────────────────────────────────────────────────────────────

        public function getUsers(): Collection
        {
            return $this->users;
        }

        // ── Permissions ───────────────────────────────────────────────────────

        public function getPermissions(): Collection
        {
            return $this->permissions;
        }

        public function addPermission(PermissionEntity $permission): self
        {
            if (!$this->permissions->contains($permission)) {
                $this->permissions[] = $permission;
                $permission->addRole($this);
            }
            return $this;
        }

        public function removePermission(PermissionEntity $permission): self
        {
            if ($this->permissions->removeElement($permission)) {
                $permission->removeRole($this);
            }
            return $this;
        }

        /**
         * Returns this role's own permissions plus all permissions inherited from
         * ancestor roles (full hierarchy traversal).
         *
         * @return PermissionEntity[]
         */
        public function getAllPermissions(): array
        {
            $permissions = $this->permissions->toArray();
            if ($this->parent !== null) {
                $permissions = array_merge($permissions, $this->parent->getAllPermissions());
            }
            return $permissions;
        }

        public function hasPermission(string $permissionName): bool
        {
            foreach ($this->getAllPermissions() as $permission) {
                if ($permission->getName() === $permissionName) {
                    return true;
                }
            }
            return false;
        }
    }
}

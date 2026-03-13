<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {

    use Doctrine\Common\Collections\ArrayCollection;
    use Doctrine\Common\Collections\Collection;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\ManyToMany;
    use Doctrine\ORM\Mapping\Table;

    /**
     * Represents a single named capability that can be granted to roles or directly to users.
     */
    #[Entity]
    #[Table(name: "authentication_permissions")]
    class PermissionEntity
    {
        #[Id]
        #[Column]
        #[GeneratedValue]
        private int $id;

        #[Column(unique: true)]
        private string $name;

        #[Column(nullable: true)]
        private ?string $description = null;

        #[Column(name: 'is_global', type: 'boolean', options: ['default' => false])]
        private bool $isGlobal = false;

        /** Roles that include this permission (inverse side of the Role ↔ Permission M2M). */
        #[ManyToMany(targetEntity: RoleEntity::class, mappedBy: "permissions")]
        private Collection $roles;

        public function __construct()
        {
            $this->roles = new ArrayCollection();
        }

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

        public function isGlobal(): bool
        {
            return $this->isGlobal;
        }

        public function setGlobal(bool $isGlobal): self
        {
            $this->isGlobal = $isGlobal;
            return $this;
        }

        public function getRoles(): Collection
        {
            return $this->roles;
        }

        public function addRole(RoleEntity $role): self
        {
            if (!$this->roles->contains($role)) {
                $this->roles[] = $role;
                $role->addPermission($this);
            }
            return $this;
        }

        public function removeRole(RoleEntity $role): self
        {
            if ($this->roles->removeElement($role)) {
                $role->removePermission($this);
            }
            return $this;
        }
    }
}

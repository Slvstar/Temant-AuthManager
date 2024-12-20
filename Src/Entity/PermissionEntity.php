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

    #[Entity]
    #[Table(name: "authentication_permissions")]
    class PermissionEntity
    {
        #[Id]
        #[Column]
        #[GeneratedValue]
        private int $id;

        #[Column]
        private string $name;

        #[Column]
        private ?string $description;

        #[ManyToMany(targetEntity: RoleEntity::class, mappedBy: "permissions")]
        private Collection $roles;

        public function __construct()
        {
            $this->roles = new ArrayCollection();
        }

        /**
         * @return int
         */
        public function getId(): int
        {
            return $this->id;
        }

        /**
         * @return string
         */
        public function getName(): string
        {
            return $this->name;
        }

        /**
         * @param string $name 
         * @return self
         */
        public function setName(string $name): self
        {
            $this->name = $name;
            return $this;
        }

        /**
         * @return string
         */
        public function getDescription(): ?string
        {
            return $this->description;
        }

        /**
         * @param ?string $description 
         * @return self
         */
        public function setDescription(?string $description): self
        {
            $this->description = $description;
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
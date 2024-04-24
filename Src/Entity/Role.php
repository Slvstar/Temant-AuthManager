<?php

namespace Temant\AuthManager\Entity {
    use Doctrine\Common\Collections\ArrayCollection;
    use Doctrine\Common\Collections\Collection;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\JoinTable;
    use Doctrine\ORM\Mapping\ManyToMany;
    use Doctrine\ORM\Mapping\OneToMany;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: "authentication_roles")]
    class Role
    {
        #[Id]
        #[Column(name: "id")]
        #[GeneratedValue]
        private int $id;

        #[Column(name: "name")]
        private string $name;

        #[Column(name: "description")]
        private string $description;

        #[OneToMany(targetEntity: User::class, mappedBy: "role")]
        private Collection $users;

        #[ManyToMany(targetEntity: Permission::class, inversedBy: "roles")]
        #[JoinTable(name: "authentication_role_permissions")]
        private Collection $permissions;

        public function __construct()
        {
            $this->permissions = new ArrayCollection();
            $this->users = new ArrayCollection();
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

        public function getDescription(): string
        {
            return $this->description;
        }

        public function setDescription(string $description): self
        {
            $this->description = $description;
            return $this;
        }

        public function getUsers(): Collection
        {
            return $this->users;
        }

        public function addUser(User $user): self
        {
            if (!$this->users->contains($user)) {
                $this->users[] = $user;
                $user->setRole($this);
            }
            return $this;
        }

        public function removeUser(User $user): self
        {
            if ($this->users->removeElement($user)) {
                if ($user->getRole() === $this) {
                    $user->setRole(null);
                }
            }
            return $this;
        }

        public function getPermissions(): Collection
        {
            return $this->permissions;
        }

        public function addPermission(Permission $permission): self
        {
            if (!$this->permissions->contains($permission)) {
                $this->permissions[] = $permission;
                $permission->addRole($this);
            }
            return $this;
        }

        public function removePermission(Permission $permission): self
        {
            if ($this->permissions->removeElement($permission)) {
                $permission->removeRole($this);
            }
            return $this;
        }
    }
}
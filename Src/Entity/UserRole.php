<?php

namespace Temant\AuthManager\Entity {
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\JoinColumn;
    use Doctrine\ORM\Mapping\ManyToOne;
    use Doctrine\ORM\Mapping\OneToOne;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: "authentication_user_role")]
    class UserRole
    {
        #[Id]
        #[Column(name: "id")]
        #[GeneratedValue]
        private int $id;

        #[Column(name: "role_id")]
        private string $roleId;

        #[Column(name: "user_id")]
        private string $userId;

        #[OneToOne(targetEntity: User::class, inversedBy: "userRole")]
        #[JoinColumn(name: "user_id", referencedColumnName: "user_id")]
        private User $user;

        #[ManyToOne(targetEntity: Role::class)]
        #[JoinColumn(name: "role_id", referencedColumnName: "id")]
        private Role $role;

        public function getRole(): Role
        {
            return $this->role;
        }

        public function setRole(Role $role): self
        {
            $this->role = $role;
            return $this;
        }

        public function getId(): int
        {
            return $this->id;
        }

        public function getUserId(): string
        {
            return $this->userId;
        }

        public function setUserId(string $userId): self
        {
            $this->userId = $userId;
            return $this;
        }

        public function getRoleId(): string
        {
            return $this->roleId;
        }

        public function setRoleId(string $roleId): self
        {
            $this->roleId = $roleId;
            return $this;
        }

        public function getUser(): User
        {
            return $this->user;
        }

        public function setUser(User $user): self
        {
            $this->user = $user;
            return $this;
        }
    }
}
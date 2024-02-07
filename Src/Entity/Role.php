<?php

namespace Temant\AuthManager\Entity {
    use Doctrine\Common\Collections\ArrayCollection;
    use Doctrine\Common\Collections\Collection;
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
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
    }
}

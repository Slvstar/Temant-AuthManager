<?php

namespace Temant\AuthManager\Entity {
    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\GeneratedValue;
    use Doctrine\ORM\Mapping\Id;
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
        public function getDescription(): string
        {
            return $this->description;
        }

        /**
         * @param string $description 
         * @return self
         */
        public function setDescription(string $description): self
        {
            $this->description = $description;
            return $this;
        }
    }
}

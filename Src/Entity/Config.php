<?php declare(strict_types=1);

namespace Temant\AuthManager\Entity {

    use Doctrine\ORM\Mapping\Column;
    use Doctrine\ORM\Mapping\Entity;
    use Doctrine\ORM\Mapping\Id;
    use Doctrine\ORM\Mapping\Table;

    #[Entity]
    #[Table(name: "authentication_configurations")]
    class Config
    {
        #[Id]
        #[Column(name: "config_key ", type: "string")]
        private string $configKey;

        #[Column(name: "config_value ", type: "string")]
        private string $configValue;

        // Getters and setters
        public function getConfigKey(): ?string
        {
            return $this->configKey;
        }

        public function setConfigKey(string $configKey): self
        {
            $this->configKey = $configKey;
            return $this;
        }

        public function getConfigValue(): ?string
        {
            return $this->configValue;
        }

        public function setConfigValue(string $configValue): self
        {
            $this->configValue = $configValue;
            return $this;
        }
    }
}

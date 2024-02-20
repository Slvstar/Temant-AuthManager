<?php declare(strict_types=1);

namespace Temant\AuthManager\Config {

    use Doctrine\ORM\EntityManager;
    use Doctrine\ORM\EntityRepository;
    use Temant\AuthManager\Entity\Config;

    /**
     * The ConfigManager class is responsible for managing configuration settings.
     * It provides methods to access and manipulate configuration data stored in the database.
     */
    class ConfigManager implements ConfigManagerInterface
    {
        private EntityRepository $config;

        /**
         * The constructor initializes the ConfigManager with an EntityManager.
         * It sets up the repository for Config entities.
         *
         * @param EntityManager $entityManager The entity manager for database operations.
         */
        public function __construct(private EntityManager $entityManager)
        {
            $this->config = $entityManager->getRepository(Config::class);
        }

        /**
         * Retrieves all configuration settings from the database.
         *
         * @return array An array of all Config entities.
         */
        public function all(): array
        {
            return $this->config->findAll();
        }

        /**
         * Retrieves the value of a specific configuration setting by its key.
         *
         * @param string $key The key of the configuration setting.
         * @return mixed The value of the configuration setting, or null if not found.
         */
        public function get(string $key): mixed
        {
            return $this->config->findOneBy(['configKey' => $key])?->getConfigValue();
        }

        /**
         * Retrieves the boolean value of a specific configuration setting.
         *
         * @param string $key The key of the configuration setting.
         * @return bool The boolean value of the configuration setting.
         */
        public function getBoolean(string $key): bool
        {
            $value = $this->get($key);
            return filter_var($value, FILTER_VALIDATE_BOOLEAN);
        }

        /**
         * Retrieves the integer value of a specific configuration setting.
         *
         * @param string $key The key of the configuration setting.
         * @return int The integer value of the configuration setting.
         */
        public function getInteger(string $key): int
        {
            $value = $this->get($key);
            return filter_var($value, FILTER_VALIDATE_INT);
        }

        /**
         * Checks if a specific configuration setting exists by its key.
         *
         * @param string $key The key of the configuration setting.
         * @return bool True if the configuration setting exists, false otherwise.
         */
        public function has(string $key): bool
        {
            return $this->config->count(['configKey' => $key]) != 0;
        }

        /**
         * Sets the value of a specific configuration setting.
         * If the setting does not exist, it creates a new Config entity and persists it.
         *
         * @param string $key The key of the configuration setting.
         * @param string $value The value to set for the configuration setting.
         * @return bool True if the setting was successfully set or created, false if it already exists.
         */
        public function set(string $key, string $value): bool
        {
            if (!$this->has($key)) {
                $config = (new Config())
                    ->setConfigKey($key)
                    ->setConfigValue($value);

                $this->entityManager->persist($config);
                $this->entityManager->flush();
                return true;
            }
            return false;
        }
    }
}
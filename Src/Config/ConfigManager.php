<?php declare(strict_types=1);

namespace Temant\AuthManager\Config {
    use Doctrine\ORM\EntityManager;
    use Doctrine\ORM\EntityRepository;
    use Temant\AuthManager\Entity\Config;

    class ConfigManager implements ConfigManagerInterface
    {
        private EntityRepository $config;

        public function __construct(private EntityManager $entityManager)
        {
            $this->config = $entityManager->getRepository(Config::class);
        }

        public function all(): array
        {
            return $this->config->findAll();
        }

        public function get(string $key): mixed
        {
            return $this->config->findOneBy(['configKey' => $key])->getConfigValue();
        }

        public function getBoolean(string $key): bool
        {
            $value = $this->get($key);
            return filter_var($value, FILTER_VALIDATE_BOOLEAN);
        }

        public function getInteger(string $key): int
        {
            $value = $this->get($key);
            return filter_var($value, FILTER_VALIDATE_INT);
        }

        public function has(string $key): bool
        {
            return $this->config->count(['configKey' => $key]) != 0;
        }

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
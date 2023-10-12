<?php declare(strict_types=1);

namespace Temant\AuthManager\Config {
    use Temant\AuthManager\Storage\StorageInterface;

    class DatabaseConfig implements ConfigInterface
    {
        public function __construct(
            private StorageInterface $storage
        ) {
        }

        public function get(string $key): ?string
        {
            return $this->storage->getColumn('auth_config', 'config_value', ['config_key' => $key]);
        }

        public function set(string $key, string $value): bool
        {
            if (!$this->has($key)) {
                return $this->storage->insertRow('auth_config', [
                    'config_key' => $key,
                    'config_value' => $value
                ]);
            }
            return false;
        }
        public function update(string $key, string $value): bool
        {
            if ($this->has($key)) {
                return $this->storage->modifyRow('auth_config', [
                    'config_key' => $key,
                    'config_value' => $value,
                ], ['config_key' => $key]);
            }
            return false;
        }

        public function has(string $key): bool
        {
            return $this->storage->rowExists('auth_config', ['config_key' => $key]);
        }

        public function all(): array
        {
            return $this->storage->getRows('auth_config');
        }
    }
}
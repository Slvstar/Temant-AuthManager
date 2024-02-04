<?php declare(strict_types=1);

namespace Temant\AuthManager\Storage {
    use Temant\DatabaseManager\DatabaseManager;

    class DatabaseStorage implements StorageInterface
    {
        public function __construct(private DatabaseManager $databaseManager)
        {
        }

        public function rowExists(string $table, ?array $conditions = null): bool
        {
            return !empty($this->getRow($table, $conditions));
        }

        public function insertRow(string $table, array $data): bool
        {
            return (bool) $this->databaseManager->insert($table, $data);
        }

        public function removeRow(string $table, ?array $conditions = null): bool
        {
            if ($conditions) {
                foreach ($conditions as $key => $value) {
                    $this->databaseManager->where($key, $value);
                }
            }
            return $this->databaseManager->delete($table);
        }

        public function modifyRow(string $table, array $data, ?array $conditions = null): bool
        {
            if ($conditions) {
                foreach ($conditions as $key => $value) {
                    if (is_array($value)) {
                        $this->databaseManager->where($key, $value[0], $value[1]);
                    } else {
                        $this->databaseManager->where($key, $value);
                    }
                }
            }
            return $this->databaseManager->update($table, $data);
        }

        public function modifyColumn(string $table, string $rowId, string $column, string $value): bool
        {
            if (!$this->columnHasValue($table, $rowId, $column, $value)) {
                return $this->databaseManager
                    ->where('the_id', $rowId)
                    ->update($table, [$column => $value]);
            }
            return false;
        }

        public function getRow(string $table, ?array $conditions = null): ?array
        {
            if ($conditions) {
                foreach ($conditions as $key => $value) {
                    if (is_array($value)) {
                        $this->databaseManager->where($key, $value[0], $value[1]);
                    } else {
                        $this->databaseManager->where($key, $value);
                    }
                }
            }
            return $this->databaseManager->selectOne($table);
        }

        public function getRows(string $table, ?array $conditions = null): array
        {
            if ($conditions) {
                foreach ($conditions as $key => $value) {
                    if (is_array($value)) {
                        $this->databaseManager->where($key, $value[0], $value[1]);
                    } else {
                        $this->databaseManager->where($key, $value);
                    }
                }
            }
            return $this->databaseManager->select($table);
        }

        public function getColumn(string $table, string $column, ?array $conditions = null): string
        {
            if ($conditions) {
                foreach ($conditions as $key => $value) {
                    if (is_array($value)) {
                        $this->databaseManager->where($key, $value[0], $value[1]);
                    } else {
                        $this->databaseManager->where($key, $value);
                    }
                }
            }
            return (string) $this->databaseManager->selectValue($table, $column);
        }

        public function columnHasValue(string $table, string $rowId, string $column, string $value): bool
        {
            return $this->databaseManager
                ->where('the_id', $rowId)
                ->selectValue($table, $column) === $value;
        }
    }
}
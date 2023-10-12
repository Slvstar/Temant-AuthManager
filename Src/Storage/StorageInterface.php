<?php declare(strict_types=1);

namespace Temant\AuthManager\Storage {
    interface StorageInterface
    {
        public function rowExists(string $source, ?array $conditions = null): bool;

        public function insertRow(string $source, array $data): bool;

        public function removeRow(string $source, ?array $conditions = null): bool;

        public function modifyRow(string $table, array $data, ?array $conditions = null): bool;

        public function modifyColumn(string $source, string $rowId, string $column, string $data): bool;

        public function getRow(string $source, ?array $conditions = null): ?array;

        public function getRows(string $table, ?array $conditions = null): array;

        public function getColumn(string $table, string $column, ?array $conditions = null): string;

        public function columnHasValue(string $source, string $rowId, string $column, string $value): bool;
    }
}
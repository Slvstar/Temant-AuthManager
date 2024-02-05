<?php declare(strict_types=1);

namespace Temant\AuthManager;

use Temant\AuthManager\Storage\StorageInterface;

class GroupPermissionsManager
{
    public function __construct(
        private StorageInterface $storage,
        private ?int $groupId = null
    ) {
    }

    public function get(): ?array
    {
        foreach ($this->storage->getRows('auth_role_permission', ['role_id' => $this->groupId]) as $permission) {
            $permissionData = $this->storage->getRow('auth_permission', ['id' => $permission['permission_id']]);
            $permissions[$permissionData['name']] = $permissionData['description'];
        }
        return isset($permissions) ? $permissions : null;
    }

    public function has(string $permission): bool
    {
        return isset($this->get()[$permission]);
    }
}
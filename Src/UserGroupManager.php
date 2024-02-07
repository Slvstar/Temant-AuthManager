<?php declare(strict_types=1);

namespace Temant\AuthManager;

use Temant\AuthManager\Storage\StorageInterface;

class UserGroupManager
{
    private ?int $id = null;
    private ?string $name = null;
    private ?string $description = null;
    public function __construct(
        private StorageInterface $storage
    ) {
    }

    public function byUserId(string $userId): ?self
    {
        $groupData = $this->storage->getRow('authentication_roles', [
            'id' => $this->storage->getColumn('auth_user_role', 'role_id', ['user_id' => $userId])
        ]);
        // If no user data is found, return null.
        if (!$groupData) {
            return null;
        }

        // Populate the object properties with user data.
        foreach ($groupData as $key => $value) {
            $this->$key = $value;
        }
        return $this;
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getName(): ?string
    {
        return $this->name;
    }
    public function getDescription(): ?string
    {
        return $this->description;
    }
}
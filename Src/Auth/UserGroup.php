<?php declare(strict_types=1);

namespace Temant\AuthManager\Auth;

use Temant\AuthManager\Storage\StorageInterface;

class UserGroup
{
    private $group;
    public function __construct(
        private StorageInterface $storage,
        private ?string $userId = null
    ) {
        $this->group = $this->storage->getRow('auth_role', [
            'id' => $this->storage->getColumn('auth_user_role', 'role_id', ['user_id' => $userId])
        ]);
    }

    public function getId()
    {
        return $this->group['id'];
    }

    public function getName()
    {
        return $this->group['name'];
    }
    public function getDescription()
    {
        return $this->group['description'];
    }
}
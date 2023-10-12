<?php declare(strict_types=1);

namespace Temant\AuthManager\Auth;

use Temant\AuthManager\Storage\StorageInterface;

class User
{
    public $user;
    public function __construct(private StorageInterface $storage, private ?string $userId)
    {
        if (is_null($userId)) {
            exit;
        }
        $this->user = $this->storage->getRow('auth_user', [
            'user_id' => $userId
        ]);
    }
    public function getId(): ?string
    {
        if (isset($this->user['user_id'])) {
            return $this->user['user_id'];
        }
        return null;
    }
    public function getPassword(): string
    {
        return $this->user['password'];
    }
    public function getFullName(): string
    {
        return sprintf('%s %s', $this->user['first_name'], $this->user['last_name']);
    }
    public function getFirstName(): string
    {
        return $this->user['first_name'];
    }
    public function getLastName(): string
    {
        return $this->user['last_name'];
    }
    public function getEmail(): string
    {
        return $this->user['email'];
    }
    public function getGroup(): ?UserGroup
    {
        return new UserGroup($this->storage, $this->userId);
    }
    public function getPermissions(): GroupPermissions
    {
        return (new GroupPermissions($this->storage, $this->getGroup()->getId()));
    }
}
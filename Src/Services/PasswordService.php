<?php

declare(strict_types=1);

namespace Temant\AuthManager\Services;

use Temant\AuthManager\Interfaces\PasswordServiceInterface;

final class PasswordService implements PasswordServiceInterface
{
    /**
     * @inheritDoc
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    /**
     * @inheritDoc
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * @inheritDoc
     */
    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_BCRYPT);
    }
}
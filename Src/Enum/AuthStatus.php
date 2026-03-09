<?php

declare(strict_types=1);

namespace Temant\AuthManager\Enum;

/**
 * Represents the result of an authentication attempt.
 */
enum AuthStatus: string
{
    /** Authentication succeeded and the user is fully logged in. */
    case SUCCESS = 'success';

    /** Credentials are valid but a 2FA code is required to complete login. */
    case REQUIRES_2FA = 'requires_2fa';

    /** Credentials were incorrect or the user was not found. */
    case FAILED = 'failed';

    /** The account has been administratively locked. */
    case ACCOUNT_LOCKED = 'account_locked';

    /** The account has not been activated yet. */
    case ACCOUNT_INACTIVE = 'account_inactive';

    /** Too many failed attempts; the user is temporarily rate-limited. */
    case TOO_MANY_ATTEMPTS = 'too_many_attempts';

    public function isSuccess(): bool
    {
        return $this === self::SUCCESS;
    }

    public function requires2FA(): bool
    {
        return $this === self::REQUIRES_2FA;
    }

    public function isFailed(): bool
    {
        return !$this->isSuccess() && !$this->requires2FA();
    }
}

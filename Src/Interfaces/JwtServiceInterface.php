<?php

declare(strict_types=1);

namespace Temant\AuthManager\Interfaces;

use Temant\AuthManager\Dto\JwtDto;
use Temant\AuthManager\Entity\UserEntity;

interface JwtServiceInterface
{
    /**
     * Issues a signed JWT for the given user.
     *
     * @param UserEntity $user   The authenticated user.
     * @param int|null   $expiry Custom TTL in seconds (overrides the configured default).
     */
    public function generate(UserEntity $user, ?int $expiry = null): string;

    /**
     * Validates a JWT string and returns its decoded payload, or null if invalid/expired.
     */
    public function validate(string $token): ?JwtDto;

    /**
     * Extracts the JTI (JWT ID) from a token without full signature verification.
     * Returns null if the token is malformed.
     */
    public function getJti(string $token): ?string;
}

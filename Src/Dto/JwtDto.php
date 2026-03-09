<?php

declare(strict_types=1);

namespace Temant\AuthManager\Dto;

/**
 * Represents the decoded, verified payload of a JWT.
 */
final readonly class JwtDto
{
    /**
     * @param int      $userId      Subject — the user's numeric ID.
     * @param string   $jti         JWT ID used for revocation tracking.
     * @param int      $issuedAt    Unix timestamp when the token was issued.
     * @param int      $expiresAt   Unix timestamp when the token expires.
     * @param string[] $roles       Role names embedded in the token.
     * @param string[] $permissions Permission names embedded in the token.
     */
    public function __construct(
        public int $userId,
        public string $jti,
        public int $issuedAt,
        public int $expiresAt,
        public array $roles,
        public array $permissions,
    ) {}

    public function isExpired(): bool
    {
        return time() > $this->expiresAt;
    }
}

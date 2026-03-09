<?php

declare(strict_types=1);

namespace Temant\AuthManager\Services;

use InvalidArgumentException;
use RuntimeException;
use Temant\AuthManager\Dto\JwtDto;
use Temant\AuthManager\Entity\UserEntity;
use Temant\AuthManager\Interfaces\JwtServiceInterface;

/**
 * Pure-PHP HS256/HS384/HS512 JWT service — no external dependencies.
 *
 * Produces compact JWTs with standard claims (sub, iat, exp, jti)
 * plus embedded roles and permissions for stateless authorization.
 */
class JwtService implements JwtServiceInterface
{
    /** Supported HMAC algorithms mapped to their hash_hmac() algorithm name. */
    private const ALGORITHMS = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * @param string $secretKey     Signing secret — must be at least 32 characters for HS256.
     * @param string $algorithm     One of HS256, HS384, HS512 (default HS256).
     * @param int    $defaultExpiry Default token lifetime in seconds (default 3600).
     *
     * @throws InvalidArgumentException if the secret is empty or the algorithm is unsupported.
     */
    public function __construct(
        private readonly string $secretKey,
        private readonly string $algorithm = 'HS256',
        private readonly int $defaultExpiry = 3600
    ) {
        if (empty($this->secretKey)) {
            throw new InvalidArgumentException('JWT secret key cannot be empty.');
        }
        if (!array_key_exists($this->algorithm, self::ALGORITHMS)) {
            throw new InvalidArgumentException("Unsupported JWT algorithm: {$this->algorithm}");
        }
    }

    public function generate(UserEntity $user, ?int $expiry = null): string
    {
        $now = time();
        $exp = $now + ($expiry ?? $this->defaultExpiry);
        $jti = bin2hex(random_bytes(16));

        $payload = [
            'sub'         => $user->getId(),
            'iat'         => $now,
            'exp'         => $exp,
            'jti'         => $jti,
            'roles'       => array_map(
                static fn($r) => $r->getName(),
                $user->getRoles()->toArray()
            ),
            'permissions' => array_map(
                static fn($p) => $p->getName(),
                $user->listPermissions()
            ),
        ];

        return $this->encode($payload);
    }

    public function validate(string $token): ?JwtDto
    {
        try {
            $payload = $this->decode($token);

            if (!isset($payload['sub'], $payload['jti'], $payload['iat'], $payload['exp'])) {
                return null;
            }

            if (time() > (int) $payload['exp']) {
                return null;
            }

            return new JwtDto(
                userId:      (int) $payload['sub'],
                jti:         (string) $payload['jti'],
                issuedAt:    (int) $payload['iat'],
                expiresAt:   (int) $payload['exp'],
                roles:       (array) ($payload['roles'] ?? []),
                permissions: (array) ($payload['permissions'] ?? []),
            );
        } catch (\Throwable) {
            return null;
        }
    }

    public function getJti(string $token): ?string
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return null;
            }
            $payload = json_decode($this->base64UrlDecode($parts[1]), true);
            return isset($payload['jti']) ? (string) $payload['jti'] : null;
        } catch (\Throwable) {
            return null;
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private function encode(array $payload): string
    {
        $header  = $this->base64UrlEncode((string) json_encode(['alg' => $this->algorithm, 'typ' => 'JWT']));
        $body    = $this->base64UrlEncode((string) json_encode($payload));
        $sig     = $this->sign("{$header}.{$body}");
        return "{$header}.{$body}.{$sig}";
    }

    private function decode(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new RuntimeException('Invalid JWT structure.');
        }

        [$header, $body, $signature] = $parts;

        // Verify algorithm matches what is configured
        $headerData = json_decode($this->base64UrlDecode($header), true);
        if (($headerData['alg'] ?? '') !== $this->algorithm) {
            throw new RuntimeException('JWT algorithm mismatch.');
        }

        // Constant-time signature check
        $expectedSig = $this->sign("{$header}.{$body}");
        if (!hash_equals($expectedSig, $signature)) {
            throw new RuntimeException('JWT signature verification failed.');
        }

        $decoded = json_decode($this->base64UrlDecode($body), true);
        if (!is_array($decoded)) {
            throw new RuntimeException('Invalid JWT payload.');
        }

        return $decoded;
    }

    private function sign(string $data): string
    {
        $algo = self::ALGORITHMS[$this->algorithm];
        return $this->base64UrlEncode(hash_hmac($algo, $data, $this->secretKey, true));
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $data): string
    {
        return (string) base64_decode(strtr($data, '-_', '+/'));
    }
}

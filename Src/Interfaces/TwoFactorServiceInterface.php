<?php

declare(strict_types=1);

namespace Temant\AuthManager\Interfaces;

interface TwoFactorServiceInterface
{
    /**
     * Generates a new random Base32-encoded TOTP secret.
     */
    public function generateSecret(): string;

    /**
     * Returns the otpauth:// URI for a QR code.
     *
     * @param string $secret Base32-encoded TOTP secret.
     * @param string $label  Account identifier shown in the authenticator (e.g. user email).
     * @param string $issuer Application name shown in the authenticator.
     */
    public function getProvisioningUri(string $secret, string $label, string $issuer): string;

    /**
     * Verifies a 6-digit TOTP code against a secret, allowing clock-drift leeway.
     *
     * @param string $secret Base32-encoded TOTP secret.
     * @param string $code   6-digit code from the authenticator app.
     * @param int    $leeway Number of time-steps (±) to accept.
     */
    public function verify(string $secret, string $code, int $leeway = 1): bool;

    /**
     * Generates a set of one-time backup codes.
     *
     * @param int $count Number of backup codes to generate.
     * @return array<string, string> Map of plaintext code → bcrypt hash.
     */
    public function generateBackupCodes(int $count = 8): array;

    /**
     * Checks a plaintext backup code against the stored hashed codes.
     *
     * @param string              $code        Code entered by the user.
     * @param array<int, string>  $hashedCodes Indexed array of bcrypt hashes.
     * @return int|false The array index of the matched code, or false if no match.
     */
    public function verifyBackupCode(string $code, array $hashedCodes): int|false;
}

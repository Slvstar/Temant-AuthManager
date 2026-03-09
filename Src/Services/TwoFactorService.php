<?php

declare(strict_types=1);

namespace Temant\AuthManager\Services;

use Temant\AuthManager\Interfaces\TwoFactorServiceInterface;
use Temant\AuthManager\Utils\TotpHelper;

/**
 * TOTP-based two-factor authentication service.
 *
 * Uses the built-in TotpHelper (RFC 6238 / RFC 4226) — no external dependencies.
 */
class TwoFactorService implements TwoFactorServiceInterface
{
    /** Length of each plaintext backup code in hex characters (10 hex = 5 bytes = 40 bits). */
    private const BACKUP_CODE_HEX_BYTES = 5;

    public function generateSecret(): string
    {
        return TotpHelper::generateSecret();
    }

    public function getProvisioningUri(string $secret, string $label, string $issuer): string
    {
        return TotpHelper::getProvisioningUri($secret, $label, $issuer);
    }

    public function verify(string $secret, string $code, int $leeway = 1): bool
    {
        return TotpHelper::verify($secret, $code, $leeway);
    }

    /**
     * {@inheritdoc}
     *
     * Each backup code is a random uppercase hex string.
     * The plaintext is returned (display once), and only the bcrypt hash is stored.
     */
    public function generateBackupCodes(int $count = 8): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $plain         = strtoupper(bin2hex(random_bytes(self::BACKUP_CODE_HEX_BYTES)));
            $codes[$plain] = password_hash($plain, PASSWORD_DEFAULT);
        }
        return $codes;
    }

    public function verifyBackupCode(string $code, array $hashedCodes): int|false
    {
        $code = strtoupper(trim($code));
        foreach ($hashedCodes as $index => $hash) {
            if (password_verify($code, $hash)) {
                return $index;
            }
        }
        return false;
    }
}

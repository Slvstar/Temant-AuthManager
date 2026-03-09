<?php

declare(strict_types=1);

namespace Temant\AuthManager\Dto;

/**
 * Holds all data needed to set up two-factor authentication for a user.
 * Present this to the user once; store only the hashed backup codes server-side.
 */
final readonly class TwoFactorSetupDto
{
    /**
     * @param string   $secret          Base32-encoded TOTP secret to store.
     * @param string   $provisioningUri otpauth:// URI — encode as a QR code for authenticator apps.
     * @param string[] $backupCodes     Plaintext backup codes shown once to the user.
     */
    public function __construct(
        public string $secret,
        public string $provisioningUri,
        public array $backupCodes,
    ) {}
}

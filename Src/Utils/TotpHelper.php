<?php

declare(strict_types=1);

namespace Temant\AuthManager\Utils;

/**
 * Pure-PHP, dependency-free TOTP (RFC 6238) implementation.
 *
 * Generates and verifies time-based one-time passwords compatible with
 * Google Authenticator, Authy, and any RFC 6238-compliant app.
 */
final class TotpHelper
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generates a random Base32-encoded TOTP secret.
     *
     * @param int $bytes Number of random bytes (20 bytes → 160-bit key, recommended by RFC 4226).
     */
    public static function generateSecret(int $bytes = 20): string
    {
        return self::base32Encode(random_bytes($bytes));
    }

    /**
     * Generates the current TOTP code for a given secret.
     *
     * @param string   $secret    Base32-encoded shared secret.
     * @param int|null $timestamp Unix timestamp (defaults to now).
     * @param int      $period    Time-step in seconds (default 30).
     */
    public static function getCode(string $secret, ?int $timestamp = null, int $period = 30): string
    {
        $timestamp ??= time();
        $counter    = intdiv($timestamp, $period);
        $key        = self::base32Decode($secret);

        // Counter as big-endian 64-bit integer
        $counterBin = pack('N*', 0) . pack('N*', $counter);
        $hmac       = hash_hmac('sha1', $counterBin, $key, true);

        // Dynamic truncation
        $offset = ord($hmac[19]) & 0x0F;
        $code   = (
            (ord($hmac[$offset])     & 0x7F) << 24 |
            (ord($hmac[$offset + 1]) & 0xFF) << 16 |
            (ord($hmac[$offset + 2]) & 0xFF) << 8  |
            (ord($hmac[$offset + 3]) & 0xFF)
        ) % 1_000_000;

        return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verifies a TOTP code, allowing a configurable time-step leeway for clock drift.
     *
     * @param string $secret Base32-encoded shared secret.
     * @param string $code   6-digit OTP submitted by the user.
     * @param int    $leeway Number of time-steps (±) to accept (default 1 = ±30 s).
     */
    public static function verify(string $secret, string $code, int $leeway = 1): bool
    {
        $timestamp = time();
        for ($i = -$leeway; $i <= $leeway; $i++) {
            if (hash_equals(self::getCode($secret, $timestamp + ($i * 30)), $code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds the otpauth:// URI used to generate QR codes for authenticator apps.
     *
     * @param string $secret Base32-encoded shared secret.
     * @param string $label  Account name (e.g. user's email address).
     * @param string $issuer Application name shown in the authenticator app.
     */
    public static function getProvisioningUri(string $secret, string $label, string $issuer): string
    {
        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
            rawurlencode($issuer . ':' . $label),
            $secret,
            rawurlencode($issuer)
        );
    }

    // ── Base32 ────────────────────────────────────────────────────────────────

    public static function base32Encode(string $data): string
    {
        $output = '';
        $v      = 0;
        $vbits  = 0;

        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $v      = ($v << 8) | ord($data[$i]);
            $vbits += 8;
            while ($vbits >= 5) {
                $vbits  -= 5;
                $output .= self::ALPHABET[($v >> $vbits) & 31];
            }
        }

        if ($vbits > 0) {
            $output .= self::ALPHABET[($v << (5 - $vbits)) & 31];
        }

        return str_pad($output, (int) (ceil(strlen($output) / 8) * 8), '=');
    }

    public static function base32Decode(string $secret): string
    {
        $secret = strtoupper(str_replace(' ', '', rtrim($secret, '=')));
        $output = '';
        $v      = 0;
        $vbits  = 0;

        for ($i = 0, $len = strlen($secret); $i < $len; $i++) {
            $pos = strpos(self::ALPHABET, $secret[$i]);
            if ($pos === false) {
                continue;
            }
            $v      = ($v << 5) | $pos;
            $vbits += 5;
            if ($vbits >= 8) {
                $vbits  -= 8;
                $output .= chr(($v >> $vbits) & 0xFF);
            }
        }

        return $output;
    }
}

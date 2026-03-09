<?php declare(strict_types=1);

use Temant\SettingsManager\Enum\SettingType;

return [

    // ── Account ───────────────────────────────────────────────────────────────

    // Allow multiple accounts to share the same email address.
    'allow_multi_users_with_same_email' => ['value' => false, 'type' => SettingType::AUTO],

    // Automatically append a numeric suffix to duplicate usernames (e.g. John.D2).
    'allow_username_increment' => ['value' => true, 'type' => SettingType::AUTO],

    // ── Email Verification ────────────────────────────────────────────────────

    // Require email verification before a newly registered account can log in.
    'mail_verify' => ['value' => false, 'type' => SettingType::AUTO],

    // Lifetime of the email-activation token in seconds (default: 1 hour).
    'mail_activation_token_lifetime' => ['value' => 3600, 'type' => SettingType::AUTO],

    // ── Password Policy ───────────────────────────────────────────────────────

    'password_min_length'        => ['value' => 8,     'type' => SettingType::AUTO],
    'password_require_uppercase' => ['value' => true,  'type' => SettingType::AUTO],
    'password_require_lowercase' => ['value' => true,  'type' => SettingType::AUTO],
    'password_require_numeric'   => ['value' => true,  'type' => SettingType::AUTO],
    'password_require_special'   => ['value' => false, 'type' => SettingType::AUTO],

    // Lifetime of the password-reset token in seconds (default: 1 hour).
    'password_reset_token_lifetime' => ['value' => 3600, 'type' => SettingType::AUTO],

    // ── Remember Me ───────────────────────────────────────────────────────────

    'remember_me_cookie_name'    => ['value' => 'temant_remember_me', 'type' => SettingType::AUTO],

    // Lifetime of the remember-me token in seconds (default: 30 days).
    'remember_me_token_lifetime' => ['value' => 2592000, 'type' => SettingType::AUTO],

    // ── Rate Limiting ─────────────────────────────────────────────────────────

    // Maximum number of failed login attempts before the user is rate-limited.
    'max_failed_attempts' => ['value' => 5, 'type' => SettingType::AUTO],

    // Window (in seconds) in which failed attempts are counted (default: 15 minutes).
    'lockout_duration' => ['value' => 900, 'type' => SettingType::AUTO],

    // ── JWT ───────────────────────────────────────────────────────────────────

    // HMAC signing secret — MUST be set to a long random string before using JWT features.
    'jwt_secret'    => ['value' => '', 'type' => SettingType::AUTO],

    // Signing algorithm: HS256, HS384, or HS512.
    'jwt_algorithm' => ['value' => 'HS256', 'type' => SettingType::AUTO],

    // Default JWT lifetime in seconds (default: 1 hour).
    'jwt_expiry'    => ['value' => 3600, 'type' => SettingType::AUTO],

    // ── Two-Factor Authentication ─────────────────────────────────────────────

    // Application name displayed inside authenticator apps (e.g. "MyApp").
    'two_factor_issuer' => ['value' => 'AuthManager', 'type' => SettingType::AUTO],

    // Number of one-time backup codes generated when 2FA is set up.
    'two_factor_backup_codes_count' => ['value' => 8, 'type' => SettingType::AUTO],
];

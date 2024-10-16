<?php declare(strict_types=1);

use Temant\SettingsManager\Enum\SettingType;

return [
    // Allows multiple users to register with the same email.
    'allow_multi_users_with_same_email' => [
        'value' => false,
        'type' => SettingType::AUTO
    ],

    // Automatically increments the username if it already exists.
    'allow_username_increment' => [
        'value' => true,
        'type' => SettingType::AUTO
    ],

    // The lifetime of the mail activation token in seconds (e.g., 3600 seconds = 1 hour).
    'mail_activation_token_lifetime' => [
        'value' => 3600,
        'type' => SettingType::AUTO
    ],

    // Enable or disable email verification after registration.
    'mail_verify' => [
        'value' => false,
        'type' => SettingType::AUTO
    ],

    // Minimum required length for user passwords.
    'password_min_length' => [
        'value' => 0,
        'type' => SettingType::AUTO
    ],

    // Enforces requirement for at least one lowercase character in passwords.
    'password_require_lowercase' => [
        'value' => false,
        'type' => SettingType::AUTO
    ],

    // Enforces requirement for at least one numeric character in passwords.
    'password_require_numeric' => [
        'value' => false,
        'type' => SettingType::AUTO
    ],

    // Enforces requirement for at least one special character in passwords.
    'password_require_special' => [
        'value' => false,
        'type' => SettingType::AUTO
    ],

    // Enforces requirement for at least one uppercase character in passwords.
    'password_require_uppercase' => [
        'value' => false,
        'type' => SettingType::AUTO
    ],

    // The lifetime of the password reset token in seconds (e.g., 3600 seconds = 1 hour).
    'password_reset_token_lifetime' => [
        'value' => 3600,
        'type' => SettingType::AUTO
    ],

    // Name of the cookie used for "remember me" functionality.
    'remember_me_cookie_name' => [
        'value' => 'temant_remember_me',
        'type' => SettingType::AUTO
    ],

    // The lifetime of the "remember me" token in seconds (e.g., 2592000 seconds = 30 days).
    'remember_me_token_lifetime' => [
        'value' => 2592000,
        'type' => SettingType::AUTO
    ]
];
<?php

declare(strict_types=1);

namespace Temant\AuthManager\Interfaces;

/**
 * PasswordServiceInterface
 *
 * Defines the contract for password hashing and verification operations.
 * This interface provides methods for securely managing user passwords including
 * hashing, verification, and rehashing when necessary. 
 */
interface PasswordServiceInterface
{
    /**
     * Hash a plaintext password using a secure hashing algorithm.
     *
     * This method should use industry-standard algorithms (e.g., bcrypt, Argon2)
     * to securely hash passwords for storage in the database.
     *
     * @param string $password The plaintext password to hash.
     *
     * @return string The hashed password.
     */
    public static function hashPassword(string $password): string;

    /**
     * Verify a plaintext password against its hash.
     *
     * Compares a provided password with a previously hashed password to
     * determine if they match. Should use constant-time comparison to
     * prevent timing attacks.
     *
     * @param string $password The plaintext password to verify.
     * @param string $hash     The hashed password to verify against.
     *
     * @return bool True if the password matches the hash, false otherwise.
     */
    public static function verifyPassword(string $password, string $hash): bool;

    /**
     * Determine if a password hash needs to be rehashed.
     *
     * Checks if a hash was created with outdated or weak hashing options
     * and should be rehashed with current security standards. This is useful
     * for upgrading password security over time.
     *
     * @param string $hash The hashed password to check.
     *
     * @return bool True if the hash should be rehashed, false otherwise.
     */
    public static function needsRehash(string $hash): bool;
}
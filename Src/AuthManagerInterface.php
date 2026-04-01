<?php

declare(strict_types=1);

namespace Temant\AuthManager;

use DateTimeInterface;
use Temant\AuthManager\Dto\JwtDto;
use Temant\AuthManager\Dto\TwoFactorSetupDto;
use Temant\AuthManager\Entity\AttemptEntity;
use Temant\AuthManager\Entity\PermissionEntity;
use Temant\AuthManager\Entity\RoleEntity;
use Temant\AuthManager\Entity\UserEntity;
use Temant\AuthManager\Enum\AuthStatus;
use Temant\AuthManager\Exceptions\EmailNotValidException;
use Temant\AuthManager\Exceptions\WeakPasswordException;
use Temant\SettingsManager\Entity\SettingEntity;

interface AuthManagerInterface
{
    // ── User registration & removal ───────────────────────────────────────────

    /**
     * Registers a new user, validates credentials, and optionally sends a verification email.
     *
     * @throws WeakPasswordException  If the password doesn't satisfy the configured policy.
     * @throws EmailNotValidException If the email address is syntactically invalid.
     */
    public function registerUser(
        string $firstName,
        string $lastName,
        string $email,
        string $password,
        ?RoleEntity $role = null
    ): ?UserEntity;

    public function removeUser(UserEntity $user): void;

    // __ Helper methods for registration/login flows (not part of the public API)
    /**
     * Generates a unique username based on the user's first and last name.
     * @param string $firstName The user's first name (e.g. "John").
     * @param string $lastName The user's last name (e.g. "Doe").
     * @return string A unique username (e.g. "John.D")
     */
    public function generateUserName(string $firstName, string $lastName): string;

    // ── Authentication ────────────────────────────────────────────────────────

    /**
     * Authenticates a user by username/email + password.
     *
     * Returns:
     *  - AuthStatus::SUCCESS          — fully logged in.
     *  - AuthStatus::REQUIRES_2FA     — credentials correct; 2FA code needed next.
     *  - AuthStatus::FAILED           — wrong credentials.
     *  - AuthStatus::ACCOUNT_INACTIVE — account not yet activated.
     *  - AuthStatus::ACCOUNT_LOCKED   — account administratively locked.
     *  - AuthStatus::TOO_MANY_ATTEMPTS — rate-limited after repeated failures.
     */
    public function authenticate(string $username, string $password, bool $remember = false): AuthStatus;

    /**
     * Passwordless authentication by email — used after the user clicks a magic-link.
     * Checks activation and lock status before creating a session.
     */
    public function authenticateWithEmail(string $email): AuthStatus;

    /**
     * Completes login for a user who was held at the REQUIRES_2FA stage.
     * Reads the pending user from the session and verifies the TOTP code.
     */
    public function verifyTwoFactor(string $code): AuthStatus;

    /**
     * Alternative to verifyTwoFactor when the user has lost access to their
     * authenticator app.  Consumes and removes the used backup code.
     */
    public function verifyTwoFactorBackupCode(string $code): AuthStatus;

    /**
     * Validates a JWT and returns the matching user entity for stateless (API) auth.
     * Returns null when the token is invalid, expired, or revoked.
     */
    public function authenticateWithJwt(string $token): ?UserEntity;

    /**
     * Destroys the current session and removes any remember-me tokens/cookies.
     */
    public function deauthenticate(): bool;

    /**
     * Returns true when a valid session or remember-me token exists.
     */
    public function isAuthenticated(): bool;

    /**
     * Returns the currently logged-in user, or null when not authenticated.
     */
    public function getLoggedInUser(): ?UserEntity;

    // ── Account status ────────────────────────────────────────────────────────

    public function activateAccount(UserEntity $user): void;

    public function deactivateAccount(UserEntity $user): void;

    public function isActivated(UserEntity $user): bool;

    public function lockAccount(UserEntity $user): void;

    public function unlockAccount(UserEntity $user): void;

    public function isLocked(UserEntity $user): bool;

    // ── Password management ───────────────────────────────────────────────────

    public function hashPassword(string $password): string;

    /**
     * Generates a password-reset token and invokes the supplied callback so the
     * application can deliver the link via email (or any other channel).
     *
     * Callback signature: fn(UserEntity $user, string $selector, string $validator): void
     */
    public function requestPasswordReset(UserEntity $user, callable $emailCallback): bool;

    /**
     * Validates the reset token and updates the user's password.
     */
    public function resetPassword(string $selector, string $validator, string $newPassword): bool;

    // ── Email verification ────────────────────────────────────────────────────

    /**
     * Validates an email-verification token and activates the account.
     */
    public function verifyAccount(string $selector, string $validator): bool;

    /**
     * Sends an activation email.  The application is responsible for the actual
     * mail transport; this method builds the message and calls PHP's mail().
     * Consider replacing it with a callback (like requestPasswordReset) for
     * production use.
     */
    public function sendEmailVerification(UserEntity $user, string $selector, string $validator): bool;

    // ── Two-factor authentication ─────────────────────────────────────────────

    /**
     * Begins the 2FA setup flow: generates a secret and backup codes.
     * Call confirm2FA() after the user successfully scans the QR code and enters a code.
     */
    public function setup2FA(UserEntity $user): TwoFactorSetupDto;

    /**
     * Confirms 2FA setup by verifying the first TOTP code.
     * After this call 2FA is enforced on every subsequent login.
     */
    public function confirm2FA(UserEntity $user, string $code): bool;

    /**
     * Disables 2FA after verifying the user's current TOTP code.
     */
    public function disable2FA(UserEntity $user, string $code): bool;

    /**
     * Regenerates backup codes (after verifying the current TOTP code).
     * Returns the new plaintext codes, or false on verification failure.
     *
     * @return string[]|false
     */
    public function regenerateBackupCodes(UserEntity $user, string $code): array|false;

    public function isTwoFactorEnabled(UserEntity $user): bool;

    // ── JWT ───────────────────────────────────────────────────────────────────

    /**
     * Issues a signed JWT for stateless (API) authentication.
     *
     * @param int|null $expiry Custom TTL in seconds; uses jwt_expiry setting when null.
     */
    public function generateJwt(UserEntity $user, ?int $expiry = null): string;

    /**
     * Verifies a JWT and returns its decoded payload, or null if invalid/revoked/expired.
     */
    public function validateJwt(string $token): ?JwtDto;

    /**
     * Adds the token's JTI to the revocation list so it cannot be used again.
     */
    public function revokeJwt(string $token): bool;

    // ── Attempt logging ───────────────────────────────────────────────────────

    public function logAuthenticationAttempt(
        UserEntity $user,
        bool $success,
        ?string $reason = null,
        ?string $ipAddress = null,
        ?string $userAgent = null
    ): bool;

    public function countFailedAuthenticationAttempts(UserEntity $user, ?DateTimeInterface $since = null): int;

    /** @return AttemptEntity[] */
    public function listAuthenticationAttempts(UserEntity $user): array;

    public function deleteAuthenticationAttempts(UserEntity $user): bool;

    public function getLastAuthenticationStatus(UserEntity $user): ?bool;

    // ── Role / Permission management ──────────────────────────────────────────

    /**
     * Creates and persists a new role.
     *
     * @param RoleEntity|null $parent Optional parent role for permission inheritance.
     */
    public function createRole(string $name, ?string $description = null, ?RoleEntity $parent = null): RoleEntity;

    public function deleteRole(RoleEntity $role): void;

    public function createPermission(string $name, ?string $description = null): PermissionEntity;

    public function deletePermission(PermissionEntity $permission): void;

    public function assignRole(UserEntity $user, RoleEntity $role): void;

    public function removeRoleFromUser(UserEntity $user, RoleEntity $role): void;

    public function assignDirectPermission(UserEntity $user, PermissionEntity $permission): void;

    public function removeDirectPermission(UserEntity $user, PermissionEntity $permission): void;

    public function addPermissionToRole(RoleEntity $role, PermissionEntity $permission): void;

    public function removePermissionFromRole(RoleEntity $role, PermissionEntity $permission): void;

    // ── Queries ───────────────────────────────────────────────────────────────

    public function getUser(int $id): ?UserEntity;

    public function getUserByUsername(string $username): ?UserEntity;

    public function getUserByEmail(string $email): ?UserEntity;

    /** @return UserEntity[] */
    public function listAllRegistredUsers(): array;

    /** @return RoleEntity[] */
    public function listAllRoles(): array;

    /** @return PermissionEntity[] */
    public function listAllPermissions(): array;

    /**
     * Checks if a user has a permission — including global permissions
     * that apply to all authenticated users regardless of assignment.
     */
    public function userHasPermission(UserEntity $user, string $permissionName): bool;

    // ── Settings ──────────────────────────────────────────────────────────────

    /** @return SettingEntity[] */
    public function listSetting(): array;
}

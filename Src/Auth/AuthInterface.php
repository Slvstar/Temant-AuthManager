<?php declare(strict_types=1);

namespace Temant\AuthManager\Auth {
    use Temant\AuthManager\Auth\Exceptions\AuthException;

    interface AuthInterface
    {
        /**
         * Authenticate a user based on their credentials.
         *
         * @param string $username
         * @param string $password
         * @return bool True if authentication succeeds, false otherwise.
         * @throws AuthException If authentication encounters an error.
         */
        public function authenticate(string $username, string $password): bool;

        /**
         * Get user data based on their username.
         *
         * @param string $username
         * @return array|null User data array or null if not found.
         * @throws AuthException If user retrieval encounters an error.
         */
        public function getUser($username);

        /**
         * Generate an authentication token for a user.
         *
         * @param string $username User data for which to generate a token.
         * @return string Generated authentication token.
         * @throws AuthException If token generation encounters an error.
         */
        public function generateToken(string $username): string;

        /**
         * Validate an authentication token.
         *
         * @param string $token Authentication token to validate.
         * @return bool True if token is valid, false otherwise.
         * @throws AuthException If token validation encounters an error.
         */
        public function validateToken(string $token): bool;

        /**
         * Logout a user by invalidating their session or token.
         *
         * @param string $username
         * @return bool True if logout is successful, false otherwise.
         * @throws AuthException If logout encounters an error.
         */
        public function logout($username): bool;

        /**
         * Change a user's password.
         *
         * @param string $username
         * @param string $newPassword
         * @return bool True if password change is successful, false otherwise.
         * @throws AuthException If password change encounters an error.
         */
        public function changePassword($username, $newPassword): bool;

        /**
         * Register a new user.
         *
         * @param array $userData User data for registration.
         * @return bool True if registration is successful, false otherwise.
         * @throws AuthException If registration encounters an error.
         */
        public function registerUser($userData): bool;

        /**
         * Verify a user's email address.
         *
         * @param string $username
         * @param string $verificationCode
         * @return bool True if verification is successful, false otherwise.
         * @throws AuthException If verification encounters an error.
         */
        public function verifyEmail($username, $verificationCode): bool;

        /**
         * Request a password reset for a user.
         *
         * @param string $username
         * @return bool True if password reset request is successful, false otherwise.
         * @throws AuthException If password reset request encounters an error.
         */
        public function requestPasswordReset($username): bool;

        /**
         * Reset a user's password after a password reset request.
         *
         * @param string $username
         * @param string $resetToken
         * @param string $newPassword
         * @return bool True if password reset is successful, false otherwise.
         * @throws AuthException If password reset encounters an error.
         */
        public function resetPassword($username, $resetToken, $newPassword): bool;

        /**
         * Check if a user is currently logged in.
         *
         * @param string $username
         * @return bool True if the user is logged in, false otherwise.
         * @throws AuthException If the check encounters an error.
         */
        public function isLoggedIn($username): bool;

        /**
         * Update user information.
         *
         * @param string $username
         * @param array $userData Updated user data.
         * @return bool True if user information is updated successfully, false otherwise.
         * @throws AuthException If the update encounters an error.
         */
        public function updateUser($username, $userData): bool;

        /**
         * Ban or suspend a user.
         *
         * @param string $username
         * @param string|null $reason Reason for banning or suspension.
         * @return bool True if user is banned or suspended successfully, false otherwise.
         * @throws AuthException If the action encounters an error.
         */
        public function banUser(string $username, $reason = null): bool;

        /**
         * Revoke a user's ban or suspension.
         *
         * @param string $username
         * @return bool True if user's ban or suspension is revoked successfully, false otherwise.
         * @throws AuthException If the action encounters an error.
         */
        public function revokeBan(string $username): bool;

        /**
         * Check if a user is banned or suspended.
         *
         * @param string $username
         * @return bool True if user's ban or suspension is revoked successfully, false otherwise.
         * @throws AuthException If the action encounters an error.
         */
        public function isBanned(string $username): bool;

        /**
         * Get user roles and permissions.
         *
         * @param string $username
         * @return array|null Associative array containing roles and permissions or null if not found.
         * @throws AuthException If retrieval encounters an error.
         */
        public function getUserRolesAndPermissions(string $username);

        /**
         * Grant a role to a user.
         *
         * @param string $username
         * @param string $role
         * @return bool True if the role is granted successfully, false otherwise.
         * @throws AuthException If the action encounters an error.
         */
        public function grantUserRole(string $username, string $role): bool;

        /**
         * Revoke a role from a user.
         *
         * @param string $username
         * @param string $role
         * @return bool True if the role is revoked successfully, false otherwise.
         * @throws AuthException If the action encounters an error.
         */
        public function revokeUserRole(string $username, string $role): bool;

        /**
         * Create a new role.
         *
         * @param string $roleName
         * @return bool True if the role is created successfully, false otherwise.
         * @throws AuthException If creation encounters an error.
         */
        public function createRole($roleName): bool;

        /**
         * Delete an existing role.
         *
         * @param string $roleName
         * @return bool True if the role is deleted successfully, false otherwise.
         * @throws AuthException If deletion encounters an error.
         */
        public function deleteRole($roleName): bool;

        /**
         * Assign permissions to a role.
         *
         * @param string $roleName
         * @param array $permissions List of permission names.
         * @return bool True if permissions are assigned successfully, false otherwise.
         * @throws AuthException If assignment encounters an error.
         */
        public function assignPermissionsToRole($roleName, $permissions): bool;

        /**
         * Revoke permissions from a role.
         *
         * @param string $roleName
         * @param array $permissions List of permission names.
         * @return bool True if permissions are revoked successfully, false otherwise.
         * @throws AuthException If revocation encounters an error.
         */
        public function revokePermissionsFromRole($roleName, $permissions): bool;

        /**
         * Check if a user has a specific permission.
         *
         * @param string $username
         * @param string $permission
         * @return bool True if the user has the permission, false otherwise.
         * @throws AuthException If the check encounters an error.
         */
        public function hasPermission($username, $permission): bool;

        /**
         * Get all available roles.
         *
         * @return array List of role names.
         * @throws AuthException If retrieval encounters an error.
         */
        public function getAllRoles();

        /**
         * Get all available permissions.
         *
         * @return array List of permission names.
         * @throws AuthException If retrieval encounters an error.
         */
        public function getAllPermissions();

        /**
         * Lock a user's account to prevent login attempts.
         *
         * @param string $username
         * @param int $lockDuration Duration of the lock in seconds.
         * @return bool True if the account is locked successfully, false otherwise.
         * @throws AuthException If locking encounters an error.
         */
        public function lockAccount($username, $lockDuration): bool;

        /**
         * Unlock a previously locked user account.
         *
         * @param string $username
         * @return bool True if the account is unlocked successfully, false otherwise.
         * @throws AuthException If unlocking encounters an error.
         */
        public function unlockAccount($username): bool;

        /**
         * Log a user's login attempt.
         *
         * @param string $username
         * @param bool $success Whether the login attempt was successful.
         * @param string|null $ipAddress IP address of the login attempt.
         * @return bool True if the login attempt is logged successfully, false otherwise.
         * @throws AuthException If logging encounters an error.
         */
        public function logLoginAttempt($username, $success, $ipAddress = null): bool;

        /**
         * Get the last login attempt status for a user.
         *
         * @param string $username
         * @return bool|null True if the last login was successful, false if failed, null if not found.
         * @throws AuthException If retrieval encounters an error.
         */
        public function getLastLoginStatus($username);

        /**
         * Count failed login attempts for a user within a specified period.
         *
         * @param string $username
         * @param int $timePeriod Time period in seconds to count failed attempts within.
         * @return int Number of failed login attempts.
         * @throws AuthException If counting encounters an error.
         */
        public function countFailedLoginAttempts($username, $timePeriod): int;

        /**
         * Hash a password securely.
         *
         * @param string $password The password to hash.
         * @return string Hashed password.
         * @throws AuthException If hashing encounters an error.
         */
        public function hashPassword(string $password): string;

        /**
         * Verify a password against its hashed version.
         *
         * @param string $password The password to verify.
         * @param string $hashedPassword The hashed password to compare against.
         * @return bool True if the password matches, false otherwise.
         * @throws AuthException If verification encounters an error.
         */
        public function verifyPassword(string $password, string $hashedPassword): bool;
    }
}
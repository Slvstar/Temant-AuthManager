<?php declare(strict_types=1);

namespace Temant\AuthManager {

    use DateTimeInterface;
    use Temant\AuthManager\Entity\Attempt;
    use Temant\AuthManager\Entity\Role;
    use Temant\AuthManager\Entity\User;
    use Temant\AuthManager\Exceptions\EmailNotValidException;
    use Temant\AuthManager\Exceptions\RoleNotFoundException;
    use Temant\AuthManager\Exceptions\WeakPasswordException;
    use Temant\SettingsManager\Entity\SettingEntity;

    interface AuthManagerInterface
    {
        /**
         * Registers a new user with the provided details.
         * 
         * @param string $firstName User's first name.
         * @param string $lastName User's last name.
         * @param int $roleId ID of the role assigned to the user.
         * @param string $email User's email address.
         * @param string $password User's chosen password.
         * 
         * @return User|null Returns the registered User or null on failure.
         * 
         * @throws RoleNotFoundException If the role ID is invalid.
         * @throws WeakPasswordException If the password does not meet security requirements.
         * @throws EmailNotValidException If the email is invalid.
         */
        public function registerUser(string $firstName, string $lastName, int $roleId, string $email, string $password): ?User;

        /**
         * Removes a user from the database.
         * 
         * @param User $user The user entity to be deleted.
         */
        public function removeUser(User $user): void;

        /**
         * Authenticates a user with provided credentials.
         * 
         * @param string $username The user's username or email.
         * @param string $password The user's password.
         * @param bool $remember Optionally remembers the user across sessions.
         * @return bool Returns true if authentication is successful, false otherwise.
         */
        public function authenticate(string $username, string $password, bool $remember = false): bool;

        /**
         * Counts failed login attempts by a user within a given time period.
         * 
         * @param User $user The user whose attempts are being counted.
         * @param DateTimeInterface|null $timePeriod The period from which to count.
         * @return int Number of failed attempts.
         */
        public function countFailedAuthenticationAttempts(User $user, ?DateTimeInterface $timePeriod = null): int;

        /**
         * Logs the user out by destroying the session and removing any tokens.
         * 
         * @return bool Returns true if logout was successful, false otherwise.
         */
        public function deauthenticate(): bool;

        /**
         * Deletes all authentication attempts for a given user.
         * 
         * @param User $user The user whose attempts are deleted.
         * @return bool Returns true if deletion was successful, false otherwise.
         */
        public function deleteAuthenticationAttempts(User $user): bool;

        /**
         * Checks the status of the user's last authentication attempt.
         * 
         * @param User $user The user whose last attempt is checked.
         * @return bool|null True if last attempt was successful, false if failed, null if no attempts exist.
         */
        public function getLastAuthenticationStatus(User $user): ?bool;

        /**
         * Checks if a user is authenticated via session or "remember me" token.
         * 
         * @return bool True if the user is authenticated, false otherwise.
         */
        public function isAuthenticated(): bool;

        /**
         * Lists all authentication attempts for a user.
         * 
         * @param User $user The user whose attempts are listed.
         * @return Attempt[] Array of attempts.
         */
        public function listAuthenticationAttempts(User $user): array;

        /**
         * Logs an authentication attempt with details such as success, IP address, and user agent.
         * 
         * @param User $user The user being logged.
         * @param bool $success True if the attempt was successful, false if not.
         * @param string|null $reason Optional reason for failure.
         * @param string|null $ipAddress Optional IP address, defaults to current IP.
         * @param string|null $userAgent Optional user agent, defaults to current user agent.
         * @return bool True if logged successfully, false otherwise.
         */
        public function logAuthenticationAttempt(User $user, bool $success, ?string $reason = null, ?string $ipAddress = null, ?string $userAgent = null): bool;

        /**
         * Activates a user account, enabling access.
         * 
         * @param User $user The user to activate.
         */
        public function activateAccount(User $user): void;

        /**
         * Deactivates a user account, disabling access.
         * 
         * @param User $user The user to deactivate.
         */
        public function deactivateAccount(User $user): void;

        /**
         * Checks if a user's account is activated.
         * 
         * @param User $user The user to check.
         * @return bool True if activated, false otherwise.
         */
        public function isActivated(User $user): bool;

        /**
         * Checks if a user's account is locked.
         * 
         * @param User $user The user to check.
         * @return bool True if locked, false otherwise.
         */
        public function isLocked(User $user): bool;

        /**
         * Locks a user account, preventing login.
         * 
         * @param User $user The user to lock.
         */
        public function lockAccount(User $user): void;

        /**
         * Unlocks a user account, allowing login.
         * 
         * @param User $user The user to unlock.
         */
        public function unlockAccount(User $user): void;

        /**
         * Fetches the currently logged-in user.
         * 
         * @return ?User Returns the User if logged in, otherwise null.
         */
        public function getLoggedInUser(): ?User;

        /**
         * Fetches a user by their username.
         * 
         * @param string $username The username to search for.
         * @return ?User The User entity, or null if not found.
         */
        public function getUserByUsername(string $username): ?User;

        /**
         * Lists all registered users.
         * 
         * @return User[] Array of all User entities.
         */
        public function listAllRegistredUsers(): array;

        /**
         * Hashes a plaintext password for secure storage.
         * 
         * @param string $password The plaintext password.
         * @return string The hashed password.
         */
        public function hashPassword(string $password): string;

        /**
         * Lists all roles in the system.
         * 
         * @return Role[] Array of all Role entities.
         */
        public function listAllRoles();

        /**
         * Generates a password reset token and triggers an email callback.
         *
         * @param User $user The email of the user requesting the password reset.
         * @param callable $emailCallback A callback function to send the reset email (e.g., sendEmail($user, $token)).
         * @return bool Returns true if the reset token is generated and email sent, false otherwise.
         */
        public function requestPasswordReset(User $user, callable $emailCallback): bool;

        /**
         * Resets the user's password after verifying the token.
         *
         * @param string $selector The token selector from the reset link.
         * @param string $validator The token validator from the reset link.
         * @param string $newPassword The new password to be set.
         * @return bool Returns true if the password is successfully reset, false otherwise.
         */
        public function resetPassword(string $selector, string $validator, string $newPassword): bool;

        /**
         * Verifies a user's account using a token.
         *
         * @param string $selector The token selector from the verification link.
         * @param string $validator The token validator from the verification link.
         * @return bool Returns true if the account is successfully verified, false otherwise.
         */
        public function verifyAccount(string $selector, string $validator): bool;

        /**
         * Sends a verification email to the user with a token for account activation.
         * 
         * @param User $user The user who needs email verification.
         * @param string $selector The token selector.
         * @param string $validator The token validator.
         * @return bool Returns true if the email was sent successfully, false otherwise.
         */
        public function sendEmailVerification(User $user, string $selector, string $validator): bool;

        /**
         * Lists all system settings.
         * 
         * @return SettingEntity[] An array of all settings.
         */
        public function listSetting(): array;
    }
}
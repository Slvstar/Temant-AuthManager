<?php declare(strict_types=1);

namespace Temant\AuthManager {

    use DateTimeInterface;
    use Temant\AuthManager\Entity\Attempt;
    use Temant\AuthManager\Entity\User;

    interface AuthManagerInterface
    {
        /**
         * Registers a new user in the system with the provided user data.
         * This method is typically called during the sign-up process
         * and involves creating a new user record in the database.
         *
         * @param string $firstName The first name of the user.
         * @param string $lastName The last name of the user.
         * @param int $roleId The role ID of the new user.
         * @param string $email The email address of the user.
         * @param string $password The password of the user.
         * @return User The newly register user Entity
         */
        public function registerUser(string $firstName, string $lastName, int $role, string $email, string $password): User;

        /**
         * Removes a specified user entity from the database. This method is responsible for deleting the user record
         * associated with the provided User object. It calls the EntityManager's remove and flush methods to ensure
         * that changes are persisted to the database. This action is irreversible, and all information related to the
         * user will be permanently deleted from the database.
         *
         * @param User $user The user entity to be removed from the database.
         */
        public function removeUser(User $user): void;

        /**
         * Sends an email to the user for email verification.
         * This method typically sends an activation link to the user's email address
         * containing the necessary parameters for account activation.
         *
         * @param User $user The user object whose email address is to be verified.
         * @param string $selector The token selector for email verification.
         * @param string $validator The token validator for email verification.
         * @return bool Returns true if the email is successfully sent, false otherwise.
         */
        public function verifyEmail(User $user, string $selector, string $validator): bool;

        /**
         * Authenticates a user by verifying their provided credentials against stored records.
         * This method is typically called during the login process to validate user login attempts.
         *
         * @param string $username The unique identifier for the user, such as username or email address.
         * @param string $password The plaintext password provided by the user for authentication.
         * @param bool $remember Optional. If set to true, the user's session will be remembered across browser sessions.
         * @return bool Returns true if the provided credentials are valid and the user is successfully authenticated, false otherwise.
         */
        public function authenticate(string $username, string $password, bool $remember = false): bool;

        /**
         * Calculates the quantity of unsuccessful authentication attempts by a specific user within a defined time frame.
         * This functionality is instrumental in enforcing security protocols
         * such as account lockouts after numerous failed login attempts,
         * enhancing the system's resilience against unauthorized access attempts.
         *
         * @param User $user The user entity whose failed authentication attempts are being counted.
         * @param DateTimeInterface|null $timePeriod The starting point in time from which to count failed attempts.
         *                  Defaults to the current time if not provided.
         * @return int The total count of failed authentication attempts by the user since the specified time.
         */
        public function countFailedAuthenticationAttempts(User $user, ?DateTimeInterface $timePeriod = null): int;

        /**
         * Terminates the current user's session and invalidates any persistent login tokens,
         * effectively logging the user out.
         * This action is a critical part of the logout process,
         * ensuring that subsequent requests require new authentication.
         * The method handles the removal of "remember me" tokens and the deletion of session data,
         * providing a secure and clean
         * logout experience.
         *
         * @return bool True if the logout process completes successfully,
         *              including the removal of any persistent tokens and session destruction.
         *              False if any part of the process fails, indicating a potential issue in the logout workflow.
         */
        public function deauthenticate(): bool;

        /**
         * Clears all recorded authentication attempts for a specified user. This function is instrumental in managing user data privacy
         * and resetting account security settings. By removing all authentication attempt records, it ensures that the user's authentication
         * history is entirely erased, providing a fresh start or aiding in security analysis.
         *
         * @param User $user The user entity whose authentication attempt records are to be purged from the system.
         * @return bool True if all authentication attempt records for the specified user are successfully deleted, indicating a complete
         *              reset of the user's authentication history. False if the deletion process encounters an error,
         *              which may require further investigation.
         */
        public function deleteAuthenticationAttempts(User $user): bool;

        /**
         * Determines the outcome of the most recent authentication attempt made by a given user. This method is useful
         * for understanding a user's last interaction with the authentication system, such as for displaying messages
         * related to their last login attempt or for audit purposes.
         *
         * @param User $user The user entity whose last authentication attempt is being queried.
         * @return bool|null True if the last attempt was successful, false if it was unsuccessful,
         * or null if there are no recorded attempts for the user.
         */
        public function getLastAuthenticationStatus(User $user): ?bool;

        /**
         * Verifies the current user's authentication status, either through an active session or a valid "remember-me" token.
         * This method is central to session management and access control, ensuring that only authenticated users can
         * access protected resources. It also handles session regeneration and clean-up of authentication attempts for
         * users authenticated via "remember-me" tokens.
         *
         * @return bool True if the user is currently authenticated either through a session or a valid "remember-me" token,
         *              false otherwise.
         */
        public function isAuthenticated(): bool;

        /**
         * Retrieves all authentication attempts made by a specific user. Useful for audit trails,
         * analyzing login patterns,
         * and detecting potential security threats through the examination of failed login attempts.
         * Each attempt includes
         * detailed information such as the timestamp, outcome (success or failure), and originating IP address.
         *
         * @param User $user The user entity whose authentication attempts are being queried.
         * @return Attempt[] An array of Attempt entities associated with the user,
         *                   providing a historical log of authentication attempts.
         */
        public function listAuthenticationAttempts(User $user): array;

        /**
         * Records a new authentication attempt for a specified user,
         * capturing critical details such as the attempt's outcome,
         * failure reason (if any), originating IP address, and user agent.
         * This function is vital for maintaining a secure audit
         * trail, monitoring authentication patterns, and facilitating investigations into security incidents.
         *
         * @param User $user The user entity for whom the authentication attempt is being logged.
         * @param bool $success Flag indicating the outcome of the attempt (true for success, false for failure).
         * @param string|null $reason Optional description of why the attempt failed,
         *                               applicable only for unsuccessful attempts.
         * @param string|null $ipAddress Optional IP address from which the attempt was made,
         *                               defaults to the current user's IP if not provided.
         * @param string|null $userAgent Optional identifier for the user agent from which the attempt originated,
         *                               defaults to the current request's user agent if not provided.
         * @return bool Indicating if the attempt was logged successfully.
         */
        public function logAuthenticationAttempt(User $user, bool $success, ?string $reason = null, ?string $ipAddress = null, ?string $userAgent = null): bool;

        /**
         * Activates a user's account to enable login and system access.
         * This method is typically invoked post-account creation or during account reactivation processes.
         *
         * @param User $user The user entity whose account is to be activated.
         */
        public function activateAccount(User $user): void;

        /**
         * Deactivates a user's account, preventing login and access to the system.
         * This method can be utilized for administrative purposes or upon a user's request for account deactivation.
         *
         * @param User $user The user entity whose account is to be deactivated.
         */
        public function deactivateAccount(User $user): void;

        /**
         * Determines if a user's account is currently activated, allowing or disallowing system access.
         *
         * @param User $user The user entity to check for activation status.
         * @return bool True if the account is activated, false otherwise.
         */
        public function isActivated(User $user): bool;

        /**
         * Assesses if a user's account is currently locked, impacting their ability to log in.
         *
         * @param User $user The user entity to check for lock status.
         * @return bool True if the account is locked, false otherwise.
         */
        public function isLocked(User $user): bool;

        /**
         * Imposes a temporary lock on a user's account, which can serve as a security measure
         * following multiple failed login attempts or for administrative purposes.
         *
         * @param User $user The user entity whose account is to be locked.
         */
        public function lockAccount(User $user): void;

        /**
         * Removes the lock from a user's account, reinstating their login capabilities.
         * This is generally used to restore access for users whose accounts were previously locked.
         *
         * @param User $user The user entity whose account is to be unlocked.
         */
        public function unlockAccount(User $user): void;

        /**
         * Fetches the currently logged-in user's profile information from the database.
         * This function queries the database for the user entity associated with the current session's user ID.
         * It's primarily used to access the logged-in user's profile data, settings, or other pertinent information
         * that is stored within their record in the system. This method ensures that only authenticated users'
         * information is retrieved, enhancing security and data integrity.
         *
         * @return User|null Returns a User entity object containing the logged-in user's information if authentication is verified,
         *                   otherwise returns null if the user is not authenticated or the user ID does not correspond to an existing record.
         */
        public function getLoggedInUser(): ?User;

        /**
         * Fetches a user's profile information from the database based on their username.
         * This function queries the database for the user entity associated with the provided username.
         * It's primarily used to retrieve a user's profile data or settings based on their username.
         * 
         * @param string $username The username of the user whose profile information is to be fetched.
         * 
         * @return User|null Returns a User entity object containing the user's information if found,
         *                   otherwise returns null if no user with the provided username exists.
         */
        public function getUserByUsername(string $username): ?User;

        /**
         * Retrieves a list of all registered users in the system.
         * This method queries the database to fetch all user entities
         * and returns them as an array, providing an overview of all
         * users currently registered in the system.
         * 
         * @return User[] An array of User entities representing all registered users in the system.
         */
        public function listAllRegistredUsers(): array;

        /**
         * Converts a plaintext password into a securely hashed version using a modern hashing algorithm.
         * This method is critical for maintaining the security of user passwords by ensuring that only hashed
         * versions are stored in the database, thereby safeguarding against potential security breaches.
         *
         * @param string $password The plaintext password to be hashed.
         * @return string The securely hashed password, suitable for storage in the database.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        public function hashPassword(string $password): string;
    }
}
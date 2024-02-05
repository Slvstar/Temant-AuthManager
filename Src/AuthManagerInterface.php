<?php declare(strict_types=1);

namespace Temant\AuthManager {

    interface AuthManagerInterface
    {
        ////////////////////////////////////////////////////////////////////
        ////////////// Authentication and Session Management ///////////////
        ////////////////////////////////////////////////////////////////////
        /**
         * Authenticates a user by verifying their provided credentials against stored records.
         * This method is typically called during the login process.
         *
         * @param string $userId The unique identifier for the user,
         * @param string $password The password provided by the user for authentication.
         * @param bool $remember Optional. If true, the user's session will be remembered across browser sessions.
         * @return bool Returns true if the credentials are valid and the user is successfully authenticated, false otherwise.
         */
        public function authenticate(string $userId, string $password, bool $remember = false): bool;

        /**
         * Checks whether a specific user is currently authenticated in the system.
         * This can be used to verify a user's login status, typically in session management.
         *
         * @param string $userId The unique identifier of the user to check.
         * @return bool Returns true if the user is currently authenticated, false otherwise.
         */
        public function isAuthenticated(string $userId): bool;

        /**
         * Deauthenticate a user by invalidating their current authentication session or token.
         * This method is called during the logout process and ensures the user must re-authenticate in future sessions.
         *
         * @return bool Returns true if the logout process is successful, false otherwise.
         */
        public function deauthenticate(): bool;

        /**
         * Retrieves the status of the last authentication attempt for a specific user.
         * This can be used for audit purposes or to provide feedback on login failures.
         *
         * @param string $userId The unique identifier of the user whose last authentication attempt status is to be retrieved.
         * @return bool|null Returns true if the last attempt was successful, false if it was unsuccessful, or null if there is no record of an attempt.
         */
        public function getLastAuthenticationStatus(string $userId);

        /**
         * Records an authentication attempt for a user, including its success or failure.
         * This is useful for security auditing and tracking login attempts.
         *
         * @param string $userId The unique identifier of the user who is attempting to authenticate.
         * @param bool $success Indicates whether the authentication attempt was successful or not.
         * @param string|null $ipAddress Optional. The IP address from which the authentication attempt was made.
         * @return bool Returns true if the attempt is logged successfully, false otherwise.
         */
        public function logAuthenticationAttempt(string $userId, bool $success, ?string $ipAddress = null): bool;

        /**
         * Counts the number of failed authentication attempts for a specific user within a given time frame.
         * This can be used as part of security measures to implement account lockout policies after a certain number of failed attempts.
         *
         * @param string $userId The unique identifier of the user.
         * @param int $timePeriod The period of time in seconds during which to count the failed attempts.
         * @return int The number of failed login attempts within the specified time period.
         */
        public function countFailedAuthenticationAttempts(string $userId, int $timePeriod): int;

        /**
         * Deletes all authentication attempts for a given user. This method can be particularly useful for clearing a user's authentication history, 
         * either as part of a privacy feature or when resetting account security settings. It ensures that no residual login attempt records remain for the user.
         *
         * @param string $userId The unique identifier of the user whose authentication attempts are to be deleted. This could be their username, email address, or any other unique identifier used within the system.
         * @return bool Returns true if all authentication attempts for the user are successfully deleted, false otherwise. A return value of true signifies a clean slate for the user's authentication history, while false indicates that an error occurred during the process.
         */
        public function deleteAuthenticationAttempts(string $userId): bool;

        /**
         * Lists all authentication attempts for a specific user. This method can be used for auditing purposes, 
         * to analyze user login patterns, or to detect potential security breaches by reviewing suspicious login attempts.
         *
         * @param string $userId The unique identifier of the user whose authentication attempts are to be listed.
         * @return array An array of authentication attempts, each containing details such as attempt timestamp, success/failure status, and IP address.
         */
        public function listAuthenticationAttempts(string $userId): array;

        ////////////////////////////////////////////////////////////////////
        /////////////////////// Password Management ////////////////////////
        ////////////////////////////////////////////////////////////////////
        /**
         * Changes the password for a given user. This method is typically used when a user wants to update their password,
         * often as part of account settings or security measures.
         *
         * @param string $userId The unique identifier of the user whose password is to be changed. This could be their username, email address, or any system-specific user ID.
         * @param string $newPassword The new password that will replace the user's current password. This password will be hashed before storage for security.
         * @return bool Returns true if the password change is successful, false otherwise. A false return value might indicate an issue with updating the user record in the storage.
         */
        public function changePassword(string $userId, string $newPassword): bool;

        ////////////////////////////////////////////////////////////////////
        ///////////////// User Management and Registration /////////////////
        ////////////////////////////////////////////////////////////////////
        /**
         * Temporarily locks a user's account for a specified duration.
         * This can be used as a security measure after a certain number of failed login attempts or for administrative reasons.
         *
         * @param string $userId The unique identifier of the user whose account is to be locked.
         * @return bool Returns true if the account is successfully locked, false otherwise.
         */
        public function lockAccount(string $userId): bool;

        /**
         * Unlocks a user's account, allowing them to login again.
         * This method can be used to restore access for a user whose account was previously locked.
         *
         * @param string $userId The unique identifier of the user whose account is to be unlocked.
         * @return bool Returns true if the account is successfully unlocked, false otherwise.
         */
        public function unlockAccount(string $userId): bool;

        /**
         * Checks whether a user's account is currently locked.
         *
         * @param string $userId The unique identifier of the user whose account lock status is to be checked.
         * @return bool Returns true if the account is currently locked, false otherwise.
         */
        public function isLocked(string $userId): bool;

        /**
         * Activates a user's account, typically used after account creation or reactivation 
         * to allow the user to login and access the system.
         *
         * @param string $userId The unique identifier of the user whose account is to be activated.
         * @return bool Returns true if the account is successfully activated, false otherwise.
         */
        public function activateAccount(string $userId): bool;

        /**
         * Deactivates a user's account, effectively preventing them from logging in and accessing the system.
         * This can be used for administrative purposes or at the user's request for account deactivation.
         *
         * @param string $userId The unique identifier of the user whose account is to be deactivated.
         * @return bool Returns true if the account is successfully deactivated, false otherwise.
         */
        public function deactivateAccount(string $userId): bool;

        /**
         * Checks whether a user's account is currently activated.
         *
         * @param string $userId The unique identifier of the user whose account activation status is to be checked.
         * @return bool Returns true if the account is currently activated, allowing login and access to the system, or false if the account is deactivated.
         */
        public function isActivated(string $userId): bool;

        /**
         * Registers a new user in the system with the provided user data.
         * This method is typically called during the sign-up process
         * and involves creating a new user record in the storage.
         *
         * @param string $firstName The first name of the user.
         * @param string $lastName The last name of the user.
         * @param string $email The E-mail of the user.
         * @param string $password The password of the user.
         * @return bool Returns true if the user is successfully registered, false otherwise.
         * for the provided data or an issue with inserting the new record into the storage.
         */
        public function registerUser(string $firstName, string $lastName, string $email, string $password): bool;

        /**
         * Retrieves a user's information from the system.
         * This method is often used to fetch user profile data, settings, or other relevant information
         * stored in the user's record.
         *
         * @param string $userId The unique identifier of the user whose information is to be retrieved.
         * @return UserManager Object containing the user's information if the user is found, or null if no user with the given ID exists.
         */
        public function getUser(string $userId);

        /**
         * Updates an existing user's information in the system.
         * This method is commonly used to allow users to modify their profile data,
         * settings, or other relevant information.
         *
         * @param string $userId The unique identifier of the user whose information is to be updated.
         * @param array $userData An associative array containing the user data to be updated. The structure of this array and the fields it contains
         * will depend on the storage schema and the information that can be updated by the user.
         * @return bool Returns true if the user's information is successfully updated, false otherwise. A false return value might indicate a validation
         * failure for the provided data, that the user does not exist, or an issue with updating the record in the storage.
         */
        public function updateUser(string $userId, array $userData): bool; 

        public function verifyEmail(string $userId, string $selector, string $validator): bool;
    }
}
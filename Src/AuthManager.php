<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use Temant\AuthManager\Config\ConfigManagerInterface;
    use Temant\AuthManager\Storage\StorageInterface;
    use Temant\AuthManager\Utils\Utils;
    use Temant\CookieManager\CookieManager;
    use Temant\SessionManager\SessionManagerInterface;

    class AuthManager implements AuthManagerInterface
    {
        private const TBL_LOGIN_ATTEMPTS = 'auth_login_attempts';
        private const TBL_AUTH_USER = 'auth_user';

        /**
         * @param SessionManagerInterface $session
         * @param StorageInterface $storage
         * @param ConfigManagerInterface $config
         * @param TokenManager $tokenManager
         */
        public function __construct(
            private SessionManagerInterface $session,
            private StorageInterface $storage,
            private ConfigManagerInterface $config,
            private TokenManager $tokenManager
        ) {
        }

        /**
         * Authenticates a user by verifying their provided credentials against stored records.
         * This method is typically called during the login process.
         *
         * @param string $userId The unique identifier for the user,
         * @param string $password The password provided by the user for authentication.
         * @param bool $remember Optional. If true, the user's session will be remembered across browser sessions.
         * @return bool Returns true if the credentials are valid and the user is successfully authenticated, false otherwise.
         */
        public function authenticate(string $userId, string $password, bool $remember = false): bool
        {
            $user = $this->getUser($userId);

            // Check if user exists
            if (!$user) {
                $this->logAuthenticationAttempt($userId, false, 'User not found');
                return false;
            }

            // Check if user is activated
            if (!$this->isActivated($userId)) {
                $this->logAuthenticationAttempt($userId, false, 'User not activated');
                return false;
            }

            // Check if password is correct
            if (!$this->verifyPassword($userId, $password)) {
                $this->logAuthenticationAttempt($userId, false, 'Wrong password');
                return false;
            }

            // At this point, all checks have passed
            $this->session->regenerate();
            $this->deleteAuthenticationAttempts($userId); // Assumes functionality to delete previous failed login attempts, if any
            $this->logAuthenticationAttempt($userId, true); // Log successful login attempt
            $this->session->set('user_id', $userId); // Set user session

            // Handle "remember me" functionality, if requested
            if ($remember) {
                $this->rememberUser($userId);
            }

            return true; // Login successful
        }

        /**
         * Remembers a user by generating a new remember-me token and storing it.
         *
         * This function generates a new remember-me token for the given user ID, removes any existing remember-me tokens
         * for that user, and stores the new token. It also sets a corresponding cookie in the user's browser to facilitate
         * automatic login on subsequent visits.
         *
         * @param string $userId The unique identifier of the user to remember.
         * @return void
         */
        private function rememberUser(string $userId): void
        {
            // Generate a new token using the TokenManager
            [$selector, $validator, $token] = TokenManager::generateToken();

            // Remove all existing tokens associated with the user ID for 'remember_me' type
            // to prevent multiple valid tokens for the same user
            $this->tokenManager->removeToken([
                'userId' => $userId,
                'type' => 'remember_me'
            ]);

            // Retrieve the token lifetime from configuration, determining how long the token should be valid
            $lifeTime = (int) $this->config->get('remember_me_token_lifetime');

            // Save the new token in the database with the user ID, selector, validator, and its lifetime
            $this->tokenManager->saveToken($userId, $this->config->get('remember_me_cookie_name'), $selector, $validator, $lifeTime);

            // Set a cookie in the user's browser with the token, using the cookie name from configuration
            // The cookie's expiration is set based on the token's lifetime
            CookieManager::set($this->config->get('remember_me_cookie_name'), $token, time() + 60 * 60 * 24 * $lifeTime);
        }

        /**
         * Counts the number of failed authentication attempts for a specific user within a given time frame.
         * This can be used as part of security measures to implement account lockout policies after a certain number of failed attempts.
         *
         * @param string $userId The unique identifier of the user.
         * @param int $timePeriod The period of time in seconds during which to count the failed attempts.
         * @return int The number of failed login attempts within the specified time period.
         */
        public function countFailedAuthenticationAttempts(string $userId, int $timePeriod): int
        {
            return count($this->storage->getRow(self::TBL_LOGIN_ATTEMPTS, [
                'user_id' => $this->$userId,
                'success' => false
            ]));
        }

        /**
         * Deauthenticate a user by invalidating their current authentication session or token.
         * This method is called during the logout process and ensures the user must re-authenticate in future sessions.
         *
         * @return bool Returns true if the logout process is successful, false otherwise.
         */
        public function deauthenticate(): bool
        {
            // delete the user token
            $this->tokenManager->removeToken([
                'userId' => $this->session->get('user_id'),
                'type' => 'remember_me'
            ]);

            // remove the remember_me cookie
            CookieManager::delete($this->config->get('remember_me_cookie_name'));

            // remove all session data
            return $this->session->destroy();
        }

        /**
         * Deletes all authentication attempts for a given user. This method can be particularly useful for clearing a user's authentication history,
         * either as part of a privacy feature or when resetting account security settings. It ensures that no residual login attempt records remain for the user.
         *
         * @param string $userId The unique identifier of the user whose authentication attempts are to be deleted. This could be their username, email address, or any other unique identifier used within the system.
         * @return bool Returns true if all authentication attempts for the user are successfully deleted, false otherwise. A return value of true signifies a clean slate for the user's authentication history, while false indicates that an error occurred during the process.
         */
        public function deleteAuthenticationAttempts(string $userId): bool
        {
            return $this->storage->removeRow(self::TBL_LOGIN_ATTEMPTS, [
                'user_id' => $userId
            ]);
        }

        /**
         * Retrieves the status of the last authentication attempt for a specific user.
         * This can be used for audit purposes or to provide feedback on login failures.
         *
         * @param string $userId The unique identifier of the user whose last authentication attempt status is to be retrieved.
         * @return bool|null Returns true if the last attempt was successful, false if it was unsuccessful, or null if there is no record of an attempt.
         */
        public function getLastAuthenticationStatus(string $userId): ?bool
        {
            return (bool) $this->storage->getColumn(self::TBL_LOGIN_ATTEMPTS, 'success', [
                'user_id' => $userId
            ]);
        }

        /**
         * Checks whether a specific user is currently authenticated in the system.
         * This can be used to verify a user's login status, typically in session management.
         *
         * @return bool Returns true if the user is currently authenticated, false otherwise.
         */
        public function isAuthenticated(): bool
        {
            if ($this->session->has('user_id')) {
                return true;
            }

            $token = filter_input(INPUT_COOKIE, $this->config->get('remember_me_cookie_name'), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
            if ($token && $this->tokenManager->isValid($token)) {
                $user = $this->findUserByToken($token);
                if ($user) {
                    $this->session->regenerate();
                    $this->deleteAuthenticationAttempts($user['user_id']);
                    $this->logAuthenticationAttempt($user['user_id'], true);
                    $this->session->set('user_id', $user['user_id']);
                    return true;
                }
            }
            return false;
        }

        /**
         * Finds a user by their remember-me token.
         *
         * This function parses the given token to extract the selector and validator components.
         * It then queries the storage to find a user associated with these token components.
         * If a matching user is found, their data is returned as an array. If no user is found, null is returned.
         *
         * @param string $token The remember-me token associated with a user.
         * @return mixed[]|null An array of user data if a user is found, or null if no user is found.
         */
        private function findUserByToken(string $token): ?array
        {
            // Parse the token to extract the selector and validator components
            [$selector, $validator] = TokenManager::parseToken($token);

            // Query the storage to find the user ID associated with the provided selector and validator
            // Then, retrieve the user's row from the 'auth_user' table using the found user ID
            return $this->storage->getRow('auth_user', ['user_id' => $this->storage->getColumn('auth_token', 'user_id', ['selector' => $selector, 'validator' => $validator])]);
        }

        /**
         * Lists all authentication attempts for a specific user. This method can be used for auditing purposes,
         * to analyze user login patterns, or to detect potential security breaches by reviewing suspicious login attempts.
         *
         * @param string $userId The unique identifier of the user whose authentication attempts are to be listed.
         * @return mixed[] An array of authentication attempts, each containing details such as attempt timestamp, success/failure status, and IP address.
         */
        public function listAuthenticationAttempts(string $userId): array
        {
            return $this->storage->getRows(self::TBL_LOGIN_ATTEMPTS, [
                'user_id' => $userId
            ]);
        }

        /**
         * Records an authentication attempt for a user, detailing the outcome, reason for failure (if applicable), IP address, and user agent. 
         * This comprehensive logging is essential for security auditing, tracking login attempts, identifying patterns, and investigating potential breaches.
         *
         * @param string $userId The unique identifier of the user attempting to authenticate
         * @param bool $success Indicates the success or failure of the authentication attempt. True for a successful attempt, false for a failed one.
         * @param string|null $reason Optional. Describes the reason for the authentication attempt's failure
         * @param string|null $ipAddress Optional. The IP address from which the authentication attempt originated.
         * @param string|null $userAgent Optional. Identifies the user agent (browser, mobile device, etc.) from which the login attempt was made.
         * @return bool Returns true if the authentication attempt is successfully logged in the system's storage, false otherwise.
         */
        public function logAuthenticationAttempt(string $userId, bool $success, ?string $reason = null, ?string $ipAddress = null, ?string $userAgent = null): bool
        {
            return $this->storage->insertRow(self::TBL_LOGIN_ATTEMPTS, [
                'user_id' => $userId,
                'success' => $success,
                'reason' => $reason,
                'ip_address' => Utils::IP(),
                'user_agent' => is_null($userAgent) ? $_SERVER['HTTP_USER_AGENT'] : $userAgent
            ]);
        }

        /**
         * Changes the password for a given user. This method is typically used when a user wants to update their password,
         * often as part of account settings or security measures.
         *
         * @param string $userId The unique identifier of the user whose password is to be changed. This could be their username, email address, or any system-specific user ID.
         * @param string $newPassword The new password that will replace the user's current password. This password will be hashed before storage for security.
         * @return bool Returns true if the password change is successful, false otherwise. A false return value might indicate an issue with updating the user record in the database.
         */
        public function changePassword(string $userId, string $newPassword): bool
        {
            return $this->storage->modifyRow(
                self::TBL_AUTH_USER,
                ['password' => $this->hashPassword($newPassword)],
                ['user_id' => $userId]
            );
        }

        /**
         * Hashes a plaintext password using a secure hashing algorithm. This method is essential for converting user passwords into a secure format before storing them in the database.
         *
         * @param string $password The plaintext password to be hashed.
         * @return string Returns the hashed version of the password. This hashed password is what should be stored in the user database, never the plaintext version.
         */
        private function hashPassword(string $password): string
        {
            return password_hash($password, PASSWORD_BCRYPT);
        }

        /**
         * Verifies that a given plaintext password matches a stored hashed password. This method is typically used during the authentication process to validate user login attempts.
         *
         * @param string $userId The unique identifier of the user.
         * @param string $password The plaintext password provided by the user during login.
         * @return bool Returns true if the plaintext password, when hashed, matches the stored hashed password, indicating a successful password match. Returns false otherwise.
         */
        private function verifyPassword(string $userId, string $password): bool
        {
            $hashedPassword = $this->storage->getColumn('auth_user', 'password', ['user_id' => $userId]);
            if (password_needs_rehash($hashedPassword, PASSWORD_BCRYPT)) {
                $this->changePassword($userId, $hashedPassword);
                $hashedPassword = $this->storage->getColumn('auth_user', 'password', ['user_id' => $userId]);
            }
            return password_verify($password, $hashedPassword);
        }

        /**
         * Activates a user's account, typically used after account creation or reactivation
         * to allow the user to login and access the system.
         *
         * @param string $userId The unique identifier of the user whose account is to be activated.
         * @return bool Returns true if the account is successfully activated, false otherwise.
         */
        public function activateAccount(string $userId): bool
        {
            return !$this->isActivated($userId)
                && $this->storage->modifyRow('auth_user', ['is_activated' => true], ['user_id' => $userId]);
        }

        /**
         * Deactivates a user's account, effectively preventing them from logging in and accessing the system.
         * This can be used for administrative purposes or at the user's request for account deactivation.
         *
         * @param string $userId The unique identifier of the user whose account is to be deactivated.
         * @return bool Returns true if the account is successfully deactivated, false otherwise.
         */
        public function deactivateAccount(string $userId): bool
        {
            return $this->isActivated($userId)
                && $this->storage->modifyRow('auth_user', ['is_activated' => false], ['user_id' => $userId]);
        }

        /**
         * Checks whether a user's account is currently activated.
         *
         * @param string $userId The unique identifier of the user whose account activation status is to be checked.
         * @return bool Returns true if the account is currently activated, allowing login and access to the system, or false if the account is deactivated.
         */
        public function isActivated(string $userId): bool
        {
            return (bool) $this->storage->getColumn('auth_user', 'is_activated', ['user_id' => $userId]);
        }

        /**
         * Checks whether a user's account is currently locked.
         *
         * @param string $userId The unique identifier of the user whose account lock status is to be checked.
         * @return bool Returns true if the account is currently locked, false otherwise.
         */
        public function isLocked(string $userId): bool
        {
            return (bool) $this->storage->getColumn('auth_user', 'is_locked', ['user_id' => $userId]);
        }

        /**
         * Temporarily locks a user's account for a specified duration.
         * This can be used as a security measure after a certain number of failed login attempts or for administrative reasons.
         *
         * @param string $userId The unique identifier of the user whose account is to be locked.
         * @return bool Returns true if the account is successfully locked, false otherwise.
         */
        public function lockAccount(string $userId): bool
        {
            return !$this->isLocked($userId)
                && $this->storage->modifyRow('auth_user', ['is_locked' => true], ['user_id' => $userId]);
        }

        /**
         * Unlocks a user's account, allowing them to login again.
         * This method can be used to restore access for a user whose account was previously locked.
         *
         * @param string $userId The unique identifier of the user whose account is to be unlocked.
         * @return bool Returns true if the account is successfully unlocked, false otherwise.
         */
        public function unlockAccount(string $userId): bool
        {
            return !$this->isLocked($userId)
                && $this->storage->modifyRow('auth_user', ['is_locked' => false], ['user_id' => $userId]);
        }

        /**
         * Generate an unique username based on the user name
         * @param string $firstName
         * @param string $lastName
         * @return string
         */
        private function generateUserId(string $firstName, string $lastName): string
        {
            $userId = sprintf('%s.%s', ucfirst($firstName), ucfirst(substr($lastName, 0, 1)));

            $count = count($this->storage->getRows('auth_user', ['user_id' => ["$userId%", 'LIKE']]));
            if ($count > 0) {
                return $userId . $count++;
            }
            return $userId;
        }

        /**
         * Retrieves a user's information from the system.
         * This method is often used to fetch user profile data, settings, or other relevant information
         * stored in the user's record.
         *
         * @param string $userId The unique identifier of the user whose information is to be retrieved.
         * @return UserManager|null Object containing the user's information if the user is found, or null if no user with the given ID exists.
         */
        public function getUser($userId): ?UserManager
        {
            return (new UserManager($this->storage))->byUserId($userId);
        }

        /**
         * Registers a new user in the system with the provided user data.
         * This method is typically called during the sign-up process
         * and involves creating a new user record in the database.
         *
         * @param string $firstName The first name of the user.
         * @param string $lastName The last name of the user.
         * @param string $email The E-mail of the user.
         * @param string $password The password of the user.
         * @return bool Returns true if the user is successfully registered, false otherwise.
         *              for the provided data or an issue with inserting the new record into the database.
         */
        function registerUser(string $firstName, string $lastName, string $email, string $password): bool
        {
            $userId = $this->generateUserId($firstName, $lastName);
            $this->storage->insertRow('auth_user', [
                'user_id' => $userId,
                'first_name' => $firstName,
                'last_name' => $lastName,
                'email' => $email,
                'password' => $this->hashPassword($password)
            ]);

            if ($this->config->get('mail_verify') === 'enabled') {
                [$selector, $validator] = TokenManager::generateToken();

                $this->tokenManager->saveToken($userId, 'email_activation', $selector, $validator, (int) $this->config->get('mail_activation_token_lifetime'));
                $this->verifyEmail($userId, $selector, $validator);
            }

            return true;
        }

        public function verifyEmail(string $userId, string $selector, string $validator): bool
        {
            $email = $this->storage->getColumn('auth_user', 'email', ['user_id' => $userId]);
            // set email subject & body
            $subject = 'Please activate your account';
            $message = <<<MESSAGE
                Hi,
                Please click the following link to activate your account:
                "https://authy/activate.php?email=$email&selector=$selector&validator=$validator"
                MESSAGE;
            // send the email
            return mail($email, $subject, nl2br($message), "From:no-reply@email.com");
        }
    }
}
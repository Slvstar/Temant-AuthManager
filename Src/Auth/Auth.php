<?php declare(strict_types=1);

namespace Temant\AuthManager\Auth {
    use Temant\AuthManager\Config\ConfigInterface;
    use Temant\AuthManager\Storage\StorageInterface;
    use Temant\AuthManager\TokenManager;
    use Temant\AuthManager\Utils\Utils;
    use Temant\CookieManager\CookieManager;
    use Temant\SessionManager\SessionManagerInterface;

    class Auth
    {
        private TokenManager $tokenManager;

        /**
         * @param SessionManagerInterface $session
         * @param StorageInterface $storage
         * @param ConfigInterface $config
         */
        public function __construct(
            private SessionManagerInterface $session,
            private StorageInterface $storage,
            private ConfigInterface $config
        ) {
            $this->tokenManager = new TokenManager($storage);
        }

        /**
         * Authenticate a user based on their credentials.
         *
         * @param string $userId
         * @param string $password
         * @param bool $remember
         * @return bool True if authentication succeeds, false otherwise.
         */
        public function login(string $userId, string $password, bool $remember = false): bool
        {
            $user = $this->getUser($userId);

            // Check if user exists
            if (!$user) {
                $this->logLoginAttempt($userId, false, 'User not found');
                return false;
            }

            // Check if user is activated
            if (!$this->isActivated($userId)) {
                $this->logLoginAttempt($userId, false, 'User not activated');
                return false;
            }

            // Check if password is correct
            if (!$this->checkPassword($userId, $password)) {
                $this->logLoginAttempt($userId, false, 'Wrong password');
                return false;
            }

            // At this point, all checks have passed
            $this->session->regenerate();
            $this->deleteLoginAttempts($userId); // Assumes functionality to delete previous failed login attempts, if any
            $this->logLoginAttempt($userId, true); // Log successful login attempt
            $this->session->set('user_id', $userId); // Set user session

            // Handle "remember me" functionality, if requested
            if ($remember) {
                $this->rememberUser($userId); // Assumes functionality to remember the user for future logins
            }

            return true; // Login successful
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
         * Register a new user.
         *
         * @param string $firstName The first name of the user.
         * @param string $lastName The last name of the user.
         * @param string $email The E-mail of the user.
         * @param string $password The password of the user.
         */
        public function registerUser(string $firstName, string $lastName, string $email, string $password)
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
                $this->sendAvtivationEmail($userId, $selector, $validator);
            }

            return true;
        }

        public function sendAvtivationEmail(string $userId, string $selector, string $validator)
        {
            $email = $this->getUserEmail($userId);
            // set email subject & body
            $subject = 'Please activate your account';
            $message = <<<MESSAGE
                Hi,
                Please click the following link to activate your account:
                "https://authy/activate.php?email=$email&selector=$selector&validator=$validator"
                MESSAGE;
            // send the email
            mail($email, $subject, nl2br($message), "From:no-reply@email.com");
        }

        /**
         * Retrieves the email of a user based on their user ID.
         * 
         * @param string $userId The userId
         * @return string a string, which is the email of the user with the specified user ID.
         */
        public function getUserEmail(string $userId): string
        {
            return $this->storage->getColumn('auth_user', 'email', ['user_id' => $userId]);
        }

        /**
         * Hash a password securely.
         * 
         * @param string $password The password to be hashed.
         * @return string a hashed version of the input password.
         */
        private function hashPassword(string $password): string
        {
            return password_hash($password, PASSWORD_BCRYPT);
        }

        /**
         * Checks if a password needs to be rehashed.
         * 
         * @param string $password The password to be checked for rehashing.
         * @return bool True if the password must rehash
         */
        private function needsRehash(string $password): bool
        {
            return password_needs_rehash($password, PASSWORD_BCRYPT);
        }

        /**
         * Checks if a given password matches the stored password for a given user ID.
         * 
         * @param string $userId
         * @param string $password
         * @return bool
         */
        private function checkPassword(string $userId, string $password): bool
        {
            $hashedPassword = $this->storage->getColumn('auth_user', 'password', ['user_id' => $userId]);
            if ($this->needsRehash($hashedPassword)) {
                $this->updatePassword($userId, $hashedPassword);
                $hashedPassword = $this->storage->getColumn('auth_user', 'password', ['user_id' => $userId]);
            }
            return password_verify($password, $hashedPassword);
        }

        /**
         * Updates the password for a user
         * 
         * @param string $userId
         * @param string $password
         * @return bool a boolean value.
         */
        private function updatePassword(string $userId, string $password): bool
        {
            return $this->storage->modifyRow(
                'auth_user',
                ['password' => $this->hashPassword($password)],
                ['user_id' => $userId]
            );
        }

        /**
         * Get user data based on their username.
         *
         * @param string $userId
         * @return User User data array or null if not found.
         */
        public function getUser($userId): User
        {
            return new User($this->storage, $userId);
        }

        public function rememberUser($userId)
        {
            [$selector, $validator, $token] = TokenManager::generateToken();
            // remove all existing token associated with the user id
            $this->tokenManager->removeToken([
                'user_id' => $userId,
                'type' => 'remember_me'
            ]);

            // set expiration date
            $lifeTime = (int) $this->config->get('remember_me_token_lifetime');

            $this->tokenManager->saveToken($userId, $this->config->get('remember_me_cookie_name'), $selector, $validator, $lifeTime);
            CookieManager::set($this->config->get('remember_me_cookie_name'), $token, time() + 60 * 60 * 24 * $lifeTime);
        }

        /**
         * Log a user's login attempt.
         *
         * @param string $userId
         * @param bool $success Whether the login attempt was successful. 
         * @return bool True if the login attempt is logged successfully, false otherwise.
         */
        public function logLoginAttempt($userId, $success = false, ?string $reason = null, ?string $userAgent = null): bool
        {
            return $this->storage->insertRow('auth_login_attempts', [
                'user_id' => $userId,
                'success' => $success,
                'reason' => $reason,
                'ip_address' => Utils::IP(),
                'user_agent' => $userAgent
            ]);
        }

        public function listLoginAttempts(string $userId): array
        {
            return $this->storage->getRows('auth_login_attempts', [
                'user_id' => $userId
            ]);
        }

        /**
         * Log a user's login attempt.
         *
         * @param string $userId 
         * @return bool True if the login attempt is logged successfully, false otherwise.
         */
        public function deleteLoginAttempts($userId): bool
        {
            return $this->storage->removeRow('auth_login_attempts', [
                'user_id' => $userId
            ]);
        }

        /**
         * Count failed login attempts for a user within a specified period.
         *
         * @param string $userId
         * @param int $timePeriod Time period in seconds to count failed attempts within.
         * @return int Number of failed login attempts.
         */
        public function countFailedLoginAttempts(string $userId, int $timePeriod = null): int
        {
            return count($this->storage->getRow('auth_login_attempts', [
                'user_id' => $this->$userId,
                'success' => false
            ]));
        }

        /**
         * Checks if a user is locked based on the userId.
         * 
         * @param string $userId The userId of the user whose lock status needs to be checked.
         * @return bool a boolean value.
         */
        public function isLocked(string $userId): bool
        {
            return (bool) $this->storage->getColumn('auth_user', 'is_locked', ['user_id' => $userId]);
        }

        /**
         * Lock a user's account to prevent login attempts.
         *
         * @param string $userId
         * @return bool True if the account is locked successfully, false otherwise.
         */
        public function lockAccount(string $userId): bool
        {
            return !$this->isLocked($userId)
                && $this->storage->modifyRow('auth_user', ['is_locked' => true], ['user_id' => $userId]);
        }

        /**
         * Unlock a previously locked user account.
         *
         * @param string $userId
         * @return bool True if the account is unlocked successfully, false otherwise.
         */
        public function unlockAccount(string $userId): bool
        {
            return $this->isLocked($userId)
                && $this->storage->modifyRow('auth_user', ['is_locked' => false], ['user_id' => $userId]);
        }

        /**
         * Checks if a user is locked based on the userId.
         * 
         * @param string $userId The userId of the user whose lock status needs to be checked.
         * @return bool a boolean value.
         */
        public function isActivated(string $userId): bool
        {
            return (bool) $this->storage->getColumn('auth_user', 'is_activated', ['user_id' => $userId]);
        }

        /**
         * Lock a user's account to prevent login attempts.
         *
         * @param string $userId
         * @return bool True if the account is locked successfully, false otherwise.
         */
        public function deactivateAccount(string $userId): bool
        {
            return !$this->isLocked($userId)
                && $this->storage->modifyRow('auth_user', ['is_activated' => true], ['user_id' => $userId]);
        }

        /**
         * Unlock a previously locked user account.
         *
         * @param string $userId
         * @return bool True if the account is unlocked successfully, false otherwise.
         */
        public function activateAccount(string $userId): bool
        {
            return !$this->isActivated($userId)
                && $this->storage->modifyRow('auth_user', ['is_activated' => true], ['user_id' => $userId]);
        }

        public function findUserByToken(string $token): ?array
        {
            [$selector, $validator] = TokenManager::parseToken($token);
            return $this->storage->getRow('auth_user', ['user_id' => $this->storage->getColumn('auth_token', 'user_id', ['selector' => $selector, 'validator' => $validator])]);
        }

        /**
         * Logout a user by invalidating their session or token.
         *
         * @return bool
         */
        public function logout(): bool
        {
            // delete the user token
            $this->tokenManager->removeToken([
                'user_id' => $this->session->get('user_id'),
                'type' => 'remember_me'
            ]);

            // remove the remember_me cookie
            CookieManager::delete($this->config->get('remember_me_cookie_name'));

            // remove all session data
            return $this->session->destroy();
        }

        public function isLoggedIn(): bool
        {
            if ($this->session->has('user_id')) {
                return true;
            }

            $token = filter_input(INPUT_COOKIE, $this->config->get('remember_me_cookie_name'), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
            if ($token && $this->tokenManager->isValid($token)) {
                $user = $this->findUserByToken($token);
                if ($user) {
                    $this->session->regenerate();
                    $this->deleteLoginAttempts($user['user_id']);
                    $this->logLoginAttempt($user['user_id'], true);
                    $this->session->set('user_id', $user['user_id']);
                    return true;
                }
            }
            return false;
        }
    }
}
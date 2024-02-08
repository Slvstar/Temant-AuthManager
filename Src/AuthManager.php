<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTime;
    use DateTimeInterface;
    use Doctrine\ORM\EntityManager;
    use Temant\AuthManager\Config\ConfigManagerInterface;
    use Temant\AuthManager\Entity\AuthenticationAttempt;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;
    use Temant\AuthManager\Utils\Utils;
    use Temant\CookieManager\CookieManager;
    use Temant\SessionManager\SessionManagerInterface;

    class AuthManager // implements AuthManagerInterface
    {
        private const TBL_AUTH_USER = 'authentication_users';

        /**
         * @param SessionManagerInterface $session
         * @param ConfigManagerInterface $configManager
         * @param TokenManager $tokenManager
         */
        public function __construct(
            private EntityManager $entityManager,
            private SessionManagerInterface $session,
            private ConfigManagerInterface $configManager,
            private TokenManager $tokenManager
        ) {
        }

        /**
         * Authenticates a user by verifying their provided credentials against stored records.
         * This method is typically called during the login process.
         *
         * @param string $username The unique identifier for the user,
         * @param string $password The password provided by the user for authentication.
         * @param bool $remember Optional. If true, the user's session will be remembered across browser sessions.
         * @return bool Returns true if the credentials are valid and the user is successfully authenticated, false otherwise.
         */
        public function authenticate(string $username, string $password, bool $remember = false): bool
        {
            $user = $this->entityManager->getRepository(User::class)->findOneBy(['username' => $username]);

            // Check if user exists
            if (!$user) {
                return false;
            }

            // Check if user is activated
            if (!$this->isActivated($user)) {
                $this->logAuthenticationAttempt($user, false, 'User not activated');
                return false;
            }

            // Check if password is correct
            if (!$this->verifyPassword($user, $password)) {
                $this->logAuthenticationAttempt($user, false, 'Wrong password');
                return false;
            }

            // At this point, all checks have passed
            $this->session->regenerate();
            $this->deleteAuthenticationAttempts($user); // Assumes functionality to delete previous failed login attempts, if any
            $this->logAuthenticationAttempt($user, true); // Log successful login attempt
            $this->session->set('user', $user); // Set user session

            // Handle "remember me" functionality, if requested
            if ($remember) {
                $this->rememberUser($user);
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
         * @param User $user The unique identifier of the user to remember.
         * @return void
         */
        private function rememberUser(User $user): void
        {
            // Generate a new token using the TokenManager.
            [$selector, $validator, $token] = $this->tokenManager->generateToken();

            // Remove all existing tokens associated with the user ID for 'remember_me'.
            $this->tokenManager
                ->removeTokensForUserByType($user, 'remember_me');

            // Get the remember me token lifetime and name from the configuration
            $lifeTime = (int) $this->configManager->get('remember_me_token_lifetime');
            $tokenName = $this->configManager->get('remember_me_cookie_name');

            // Save the new token in the database with the user ID, selector, validator, and its lifetime
            $this->tokenManager->saveToken($user, $tokenName, $selector, $validator, $lifeTime);

            // Set a cookie in the user's browser with the token, using the cookie name from configuration
            // The cookie's expiration is set based on the token's lifetime
            CookieManager::set($tokenName, $token, time() + 60 * 60 * 24 * $lifeTime);
        }

        /**
         * Counts the number of failed authentication attempts for a specific user within a given time frame.
         * This can be used as part of security measures to implement account lockout policies after a certain number of failed attempts.
         *
         * @param User $user The unique identifier of the user.
         * @param int $timePeriod The period of time in seconds during which to count the failed attempts.
         * @return int The number of failed login attempts within the specified time period.
         */
        public function countFailedAuthenticationAttempts(User $user, DateTimeInterface $timePeriod = new DateTime): int
        {
            return $user->getAttempts()
                ->filter(
                    fn(AuthenticationAttempt $attempt): bool =>
                    $attempt->getSuccess() === false
                    && $attempt->getCreatedAt() >= $timePeriod
                )
                ->count();
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
            if ($this->getLoggedInUser()) {
                $this->tokenManager
                    ->removeTokensForUserByType($this->getLoggedInUser(), 'remember_me');
            }

            // remove the remember_me cookie
            CookieManager::delete($this->configManager->get('remember_me_cookie_name'));

            // remove all session data
            return $this->session->destroy();
        }

        /**
         * Deletes all authentication attempts for a given user. This method can be particularly useful for clearing a user's authentication history,
         * either as part of a privacy feature or when resetting account security settings. It ensures that no residual login attempt records remain for the user.
         *
         * @param User $user The unique identifier of the user whose authentication attempts are to be deleted. This could be their username, email address, or any other unique identifier used within the system.
         * @return bool Returns true if all authentication attempts for the user are successfully deleted, false otherwise. A return value of true signifies a clean slate for the user's authentication history, while false indicates that an error occurred during the process.
         */
        public function deleteAuthenticationAttempts(User $user): bool
        {
            return (bool) $this->entityManager
                ->getRepository(AuthenticationAttempt::class)
                ->createQueryBuilder('a')
                ->delete()
                ->where('a.user = :user')
                ->setParameter('user', $user)
                ->getQuery()->execute();
        }

        /**
         * Retrieves the status of the last authentication attempt for a specific user.
         *
         * @param User $user The unique identifier of the user.
         * @return bool|null Returns true if the last attempt was successful, false if unsuccessful, or null if no record exists.
         */
        public function getLastAuthenticationStatus(User $user): ?bool
        {
            /** @var AuthenticationAttempt */
            $lastAttempt = $user->getAttempts()->last();
            return ($lastAttempt instanceof AuthenticationAttempt)
                ? $lastAttempt->getSuccess()
                : null;
        }

        /**
         * Checks whether a specific user is currently authenticated in the system.
         * This can be used to verify a user's login status, typically in session management.
         *
         * @return bool Returns true if the user is currently authenticated, false otherwise.
         */
        public function isAuthenticated(): bool
        {
            if ($this->session->has('user')) {
                return true;
            }

            $token = filter_input(INPUT_COOKIE, $this->configManager->get('remember_me_cookie_name'), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
            if ($token && $this->tokenManager->isValid($token)) {
                $user = $this->findUserByToken($token);
                if ($user) {
                    $this->session->regenerate();
                    $this->deleteAuthenticationAttempts($user);
                    $this->logAuthenticationAttempt($user, true);
                    $this->session->set('user', $user);
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
         * @return User|null An array of user data if a user is found, or null if no user is found.
         */
        private function findUserByToken(string $token): User
        {
            // Parse the token to extract the selector and validator components
            [$selector] = $this->tokenManager->parseToken($token);
            return $this->entityManager
                ->getRepository(Token::class)
                ->findOneBy(['selector' => $selector])
                ->getUser();
        }

        /**
         * Lists all authentication attempts for a specific user. This method can be used for auditing purposes,
         * to analyze user login patterns, or to detect potential security breaches by reviewing suspicious login attempts.
         *
         * @param User $user The unique identifier of the user whose authentication attempts are to be listed.
         * @return AuthenticationAttempt[] An array of authentication attempts, each containing details such as attempt timestamp, success/failure status, and IP address.
         */
        public function listAuthenticationAttempts(User $user): array
        {
            return $user->getAttempts()->toArray();
        }

        /**
         * Records an authentication attempt for a user, detailing the outcome, reason for failure (if applicable), IP address, and user agent. 
         * This comprehensive logging is essential for security auditing, tracking login attempts, identifying patterns, and investigating potential breaches.
         *
         * @param User $user The unique identifier of the user attempting to authenticate
         * @param bool $success Indicates the success or failure of the authentication attempt. True for a successful attempt, false for a failed one.
         * @param string|null $reason Optional. Describes the reason for the authentication attempt's failure
         * @param string|null $ipAddress Optional. The IP address from which the authentication attempt originated.
         * @param string|null $userAgent Optional. Identifies the user agent (browser, mobile device, etc.) from which the login attempt was made.
         * @return bool Returns true if the authentication attempt is successfully logged in the system's storage, false otherwise.
         */
        public function logAuthenticationAttempt(User $user, bool $success, ?string $reason = null, ?string $ipAddress = null, ?string $userAgent = null): bool
        {
            $attempt = (new AuthenticationAttempt)
                ->setUser($user)
                ->setSuccess($success)
                ->setReason($reason)
                ->setIpAddress($ipAddress ?: Utils::IP())
                ->setUserAgent($userAgent ?: $_SERVER['HTTP_USER_AGENT']);

            $this->entityManager->persist($attempt);
            $this->entityManager->flush();

            return true;
        }

        /**
         * Changes the password for a given user. This method is typically used when a user wants to update their password,
         * often as part of account settings or security measures.
         *
         * @param User $user The unique identifier of the user whose password is to be changed. This could be their username, email address, or any system-specific user ID.
         * @param string $newPassword The new password that will replace the user's current password. This password will be hashed before storage for security.
         */
        public function changePassword(User $user, string $newPassword): void
        {
            $user->setPassword($this->hashPassword($newPassword));
            $this->entityManager->flush();
        }

        /**
         * Hashes a plaintext password using a secure hashing algorithm. This method is essential for converting user passwords into a secure format before storing them in the database.
         *
         * @param string $password The plaintext password to be hashed.
         * @return string Returns the hashed version of the password. This hashed password is what should be stored in the user database, never the plaintext version.
         */
        private function hashPassword(string $password): string
        {
            return password_hash($password, PASSWORD_DEFAULT, ["cost" => 12]);
        }

        /**
         * Verifies that a given plaintext password matches a stored hashed password. This method is typically used during the authentication process to validate user login attempts.
         *
         * @param User $user The unique identifier of the user.
         * @param string $password The plaintext password provided by the user during login.
         * @return bool Returns true if the plaintext password, when hashed, matches the stored hashed password, indicating a successful password match. Returns false otherwise.
         */
        private function verifyPassword(User $user, string $password): bool
        {
            $hashedPassword = $user->getPassword();

            if (password_needs_rehash($hashedPassword, PASSWORD_DEFAULT, ["cost" => 12])) {
                $this->changePassword($user, $hashedPassword);
            }
            return password_verify($password, $hashedPassword);
        }

        /**
         * Activates a user's account, typically used after account creation or reactivation
         * to allow the user to login and access the system.
         *
         * @param User $user The unique identifier of the user whose account is to be activated. 
         */
        public function activateAccount(User $user): void
        {
            $user->setIsActivated(true);
            $this->entityManager->flush();
        }

        /**
         * Deactivates a user's account, effectively preventing them from logging in and accessing the system.
         * This can be used for administrative purposes or at the user's request for account deactivation.
         *
         * @param User $user The unique identifier of the user whose account is to be deactivated.
         */
        public function deactivateAccount(User $user): void
        {
            $user->setIsActivated(false);
            $this->entityManager->flush();
        }

        /**
         * Checks whether a user's account is currently activated.
         *
         * @param User $user The unique identifier of the user whose account activation status is to be checked.
         * @return bool Returns true if the account is currently activated, allowing login and access to the system, or false if the account is deactivated.
         */
        public function isActivated(User $user): bool
        {
            return $user->getIsActivated();
        }

        /**
         * Checks whether a user's account is currently locked.
         *
         * @param User $user The unique identifier of the user whose account lock status is to be checked.
         * @return bool Returns true if the account is currently locked, false otherwise.
         */
        public function isLocked(User $user): bool
        {
            return $user->getIsLocked();
        }

        /**
         * Temporarily locks a user's account for a specified duration.
         * This can be used as a security measure after a certain number of failed login attempts or for administrative reasons.
         *
         * @param User $user The unique identifier of the user whose account is to be locked.
         */
        public function lockAccount(User $user): void
        {
            $user->setIsLocked(true);
            $this->entityManager->flush();
        }

        /**
         * Unlocks a user's account, allowing them to login again.
         * This method can be used to restore access for a user whose account was previously locked.
         *
         * @param User $user The unique identifier of the user whose account is to be unlocked.
         */
        public function unlockAccount(User $user): void
        {
            $user->setIsLocked(false);
            $this->entityManager->flush();
        }

        /**
         * Generate an unique username based on the user name
         * @param string $firstName
         * @param string $lastName
         * @return string
         */
        private function generateUserName(string $firstName, string $lastName): string
        {
            $username = sprintf('%s.%s', ucfirst($firstName), ucfirst(substr($lastName, 0, 1)));

            $currentUsers = count($this->entityManager
                ->getRepository(User::class)
                ->createQueryBuilder('u')
                ->select('u.username')
                ->where('u.username LIKE :username')
                ->setParameter('username', "$username%")
                ->getQuery()
                ->execute());

            if ($currentUsers > 0) {
                return $username . ++$currentUsers;
            }
            return $username;
        }

        /**
         * Retrieves a user's information from the system.
         * This method is often used to fetch user profile data, settings, or other relevant information
         * stored in the user's record.
         *
         * @return User|null Object containing the user's information if the user is found, or null if no user with the given ID exists.
         */
        public function getLoggedInUser(): ?User
        {
            if ($this->isAuthenticated()) {
                return $this->entityManager
                    ->getRepository(User::class)
                    ->find($this->session->get('user'));
            }
            return null;
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
            $username = $this->generateUserName($firstName, $lastName);

            $newUser = (new User)
                ->setUserName($username)
                ->setFirstName($firstName)
                ->setLastName($lastName)
                ->setEmail($email)
                ->setPassword($this->hashPassword($password))
                ->setIsActivated(false)
                ->setIsLocked(false);
            $this->entityManager->persist($newUser);
            $this->entityManager->flush();

            $user = $this->entityManager->getRepository(User::class)->findOneBy(['username' => $username]);

            if ($this->configManager->get('mail_verify') === 'enabled') {
                [$selector, $validator] = $this->tokenManager->generateToken();

                $this->tokenManager->saveToken($user, 'email_activation', $selector, $validator, (int) $this->configManager->get('mail_activation_token_lifetime'));
                $this->verifyEmail($user, $selector, $validator);
            }

            return true;
        }

        public function verifyEmail(User $user, string $selector, string $validator): bool
        {
            $email = $this->entityManager->getRepository(User::class)->find($user)->getEmail();

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
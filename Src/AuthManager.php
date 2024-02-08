<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTime;
    use DateTimeInterface;
    use Doctrine\ORM\EntityManager;
    use Exception;
    use Temant\AuthManager\Config\ConfigManagerInterface;
    use Temant\AuthManager\Entity\AuthenticationAttempt;
    use Temant\AuthManager\Entity\Role;
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
         * Activates a user's account to enable login and system access.
         * This method is typically invoked post-account creation or during account reactivation processes.
         *
         * @param User $user The user entity whose account is to be activated.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         * @see User::setIsActivated() Related method to set the activation status.
         * @uses EntityManager::flush() To persist changes to the database.
         */
        public function activateAccount(User $user): void
        {
            $user->setIsActivated(true);
            $this->entityManager->flush();
        }

        /**
         * Deactivates a user's account, preventing login and access to the system.
         * This method can be utilized for administrative purposes or upon a user's request for account deactivation.
         *
         * @param User $user The user entity whose account is to be deactivated.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         * @see User::setIsActivated() Related method to set the activation status.
         * @uses EntityManager::flush() To persist changes to the database.
         */
        public function deactivateAccount(User $user): void
        {
            $user->setIsActivated(false);
            $this->entityManager->flush();
        }

        /**
         * Determines if a user's account is currently activated, allowing or disallowing system access.
         *
         * @param User $user The user entity to check for activation status.
         * @return bool True if the account is activated, false otherwise.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         * @see User::getIsActivated() Used to retrieve the user's activation status.
         */
        public function isActivated(User $user): bool
        {
            return $user->getIsActivated();
        }

        /**
         * Assesses if a user's account is currently locked, impacting their ability to log in.
         *
         * @param User $user The user entity to check for lock status.
         * @return bool True if the account is locked, false otherwise.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         * @see User::getIsLocked() Used to retrieve the user's lock status.
         */
        public function isLocked(User $user): bool
        {
            return $user->getIsLocked();
        }

        /**
         * Imposes a temporary lock on a user's account, which can serve as a security measure
         * following multiple failed login attempts or for administrative purposes.
         *
         * @param User $user The user entity whose account is to be locked.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         * @see User::setIsLocked() Related method to set the lock status.
         * @uses EntityManager::flush() To persist changes to the database.
         */
        public function lockAccount(User $user): void
        {
            $user->setIsLocked(true);
            $this->entityManager->flush();
        }

        /**
         * Removes the lock from a user's account, reinstating their login capabilities.
         * This is generally used to restore access for users whose accounts were previously locked.
         *
         * @param User $user The user entity whose account is to be unlocked.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         * @see User::setIsLocked() Related method to set the lock status.
         * @uses EntityManager::flush() To persist changes to the database.
         */
        public function unlockAccount(User $user): void
        {
            $user->setIsLocked(false);
            $this->entityManager->flush();
        }

        /**
         * Generates a unique username based on the provided first name and last initial.
         * This method constructs a base username by concatenating the capitalized first name with
         * the capitalized initial of the last name. It then checks for existing usernames that start
         * with this base username. If such usernames exist, it appends a number to the base username
         * to ensure uniqueness. The number appended is one more than the count of existing usernames
         * with the same pattern.
         *
         * @param string $firstName The first name of the user.
         * @param string $lastName The last name of the user.
         * @return string The generated unique username.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08 
         * @example generateUserName('John', 'Doe') // Returns 'John.D1' if 'John.D' already exists.
         *
         * @internal Used internally for user registration, not intended for external use.
         */
        private function generateUserName(string $firstName, string $lastName): string
        {
            $usernameBase = sprintf('%s.%s', ucfirst($firstName), ucfirst(substr($lastName, 0, 1)));

            // Retrieve users with usernames starting with the base username
            $existingUsernames = array_map(fn(User $user): string =>
                $user->getUserName(), $this->entityManager->getRepository(User::class)->findAll());

            // Filter usernames to find those that match the pattern
            $matchingUsernames = array_filter($existingUsernames, fn($username): bool =>
                str_starts_with($username, $usernameBase));

            // Count matching usernames to determine the new username's suffix
            $countMatchingUsernames = count($matchingUsernames);

            // If there are matching usernames, append the count + 1 to the base username
            if ($countMatchingUsernames > 0) {
                return $usernameBase . ($countMatchingUsernames + 1);
            }

            // If there are no matching usernames, return the base username
            return $usernameBase;
        }

        /**
         * Fetches the currently logged-in user's profile information from the database.
         * This function queries the database for the user entity associated with the current session's user ID.
         * It's primarily used to access the logged-in user's profile data, settings, or other pertinent information
         * that is stored within their record in the system. This method ensures that only authenticated users'
         * information is retrieved, enhancing security and data integrity.
         *
         * @return User|null Returns a User entity object containing the logged-in user's information if authentication is verified,
         *                   otherwise returns null if the user is not authenticated or the user ID does not correspond to an existing record.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         * @see User For the structure of the User entity.
         * @see isAuthenticated() To check the user's authentication status.
         * @uses Session::get() To retrieve the user ID from the session.
         * @uses EntityManager::find() To fetch the User entity from the database.
         */
        public function getLoggedInUser(): ?User
        {
            // Check if the user is authenticated
            if (!$this->isAuthenticated()) {
                return null;
            }

            // Retrieve the user ID stored in the session
            $userId = $this->session->get('user');

            // Fetch and return the User entity associated with the logged-in user's ID
            return $this->entityManager
                ->getRepository(User::class)
                ->find($userId);
        }

        /**
         * Registers a new user in the system with the provided user data.
         * This method is typically called during the sign-up process
         * and involves creating a new user record in the database.
         *
         * @param string $firstName The first name of the user.
         * @param string $lastName The last name of the user.
         * @param int $role The role Id of the new created User
         * @param string $email The E-mail of the user.
         * @param string $password The password of the user.
         * @return bool Returns true if the user is successfully registered, false otherwise.
         *              for the provided data or an issue with inserting the new record into the database.
         */
        function registerUser(string $firstName, string $lastName, int $role, string $email, string $password): bool
        {
            // Generate a username based on the provided first and last name
            $username = $this->generateUserName($firstName, $lastName);

            // Create a new User entity and set its properties
            $newUser = (new User)
                ->setUserName($username)
                ->setFirstName($firstName)
                ->setLastName($lastName)
                ->setEmail($email)
                ->setPassword($this->hashPassword($password))
                ->setIsActivated(false)
                ->setIsLocked(false);

            // Retrieve the desired Role entity from the database
            $role = $this->entityManager->getRepository(Role::class)->find($role);

            if (!$role) {
                throw new Exception("User Role Is Not Found!", 1);
            }

            // Set the Role on the new User entity
            $newUser->setRole($role);

            // Persist the new User entity to the database
            $this->entityManager->persist($newUser);
            $this->entityManager->flush();

            // Additional logic for email verification, etc.
            if ($this->configManager->get('mail_verify') === 'enabled') {
                [$selector, $validator] = $this->tokenManager->generateToken();

                $this->tokenManager->saveToken($newUser, 'email_activation', $selector, $validator, (int) $this->configManager->get('mail_activation_token_lifetime'));
                $this->verifyEmail($newUser, $selector, $validator);
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
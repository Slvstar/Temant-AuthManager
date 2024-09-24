<?php declare(strict_types=1);

namespace Temant\AuthManager {

    use DateTime;
    use DateTimeInterface;
    use Doctrine\ORM\EntityManager;
    use Temant\AuthManager\Entity\Attempt;
    use Temant\AuthManager\Entity\Role;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;
    use Temant\AuthManager\Exceptions\EmailNotValidException;
    use Temant\AuthManager\Exceptions\RoleNotFoundException;
    use Temant\AuthManager\Exceptions\UsernameIncrementException;
    use Temant\AuthManager\Exceptions\WeakPasswordException;
    use Temant\AuthManager\Utils\Utils;
    use Temant\AuthManager\Utils\Validator;
    use Temant\CookieManager\CookieManager;
    use Temant\SessionManager\SessionManagerInterface;
    use Temant\SettingsManager\SettingsManager;

    /**
     * AuthManager is responsible for managing the authentication and authorization process.
     * It handles user registration, login, token management, and account status modifications.
     */
    final class AuthManager implements AuthManagerInterface
    {
        /**
         * The cost factor for bcrypt password hashing.
         * 
         * @var int
         */
        private const int PASSWORD_COST = 12;

        /**
         * Manages settings related to authentication.
         *
         * @var SettingsManager
         */
        private readonly SettingsManager $settingsManager;


        /**
         * Token manager responsible for token operations such as creation, validation, and renewal.
         * 
         * @var TokenManager
         */
        private readonly TokenManager $tokenManager;

        /**
         * AuthManager constructor to initialize dependencies.
         * 
         * @param EntityManager $entityManager Manages database operations.
         * @param SessionManagerInterface $sessionManagerInterface Handles user session management.
         */
        public function __construct(
            private readonly EntityManager $entityManager,
            private readonly SessionManagerInterface $sessionManagerInterface
        ) {
            $this->settingsManager = new SettingsManager($entityManager, "authentication_settings");
            $this->tokenManager = new TokenManager($entityManager);
        }

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
        public function registerUser(string $firstName, string $lastName, int $roleId, string $email, string $password): ?User
        {
            // Generate a username based on the provided first and last name
            $username = $this->generateUserName($firstName, $lastName);

            // Password validation checks
            $validatedPassword = Validator::validatePassword($password, [
                'min_length' => $this->getSetting('password_min_length'),
                'require_uppercase' => $this->getSetting('password_require_uppercase'),
                'require_lowercase' => $this->getSetting('password_require_lowercase'),
                'require_numeric' => $this->getSetting('password_require_numeric'),
                'require_special' => $this->getSetting('password_require_special')
            ]);

            // Create a new User entity and set its properties
            $newUser = (new User)
                ->setUserName($username)
                ->setFirstName($firstName)
                ->setLastName($lastName)
                ->setEmail(Validator::validateEmail($email))
                ->setPassword($this->hashPassword($validatedPassword))
                ->setIsActivated(false)
                ->setIsLocked(false)
                ->setRole(Validator::validateRole($this->entityManager, $roleId));

            // Persist the new User entity to the database
            $this->entityManager->persist($newUser);
            $this->entityManager->flush();

            // Additional logic for email verification, if enabled
            if ($this->getSetting(key: 'mail_verify')) {
                $tokenDto = $this->tokenManager->generateToken();

                $this->tokenManager->saveToken($newUser, 'email_activation', $tokenDto->selector, $tokenDto->hashedValidator, $this->getSetting('mail_activation_token_lifetime'));
                $this->sendEmailVerification($newUser, $tokenDto->selector, $tokenDto->plainValidator);
            }

            return $this->entityManager->getRepository(User::class)->find($newUser);
        }

        /**
         * Removes a user from the database.
         * 
         * @param User $user The user entity to be deleted.
         */
        public function removeUser(User $user): void
        {
            $this->entityManager->remove($user);
            $this->entityManager->flush();
        }

        /**
         * Authenticates a user with provided credentials.
         * 
         * @param string $username The user's username or email.
         * @param string $password The user's password.
         * @param bool $remember Optionally remembers the user across sessions.
         * @return bool Returns true if authentication is successful, false otherwise.
         */
        public function authenticate(string $username, string $password, bool $remember = false): bool
        {
            // Retrieve the user entity based on the provided username
            if (filter_var($username, FILTER_VALIDATE_EMAIL)) {
                $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $username]);
            } else {
                $user = $this->entityManager->getRepository(User::class)->findOneBy(['username' => $username]);
            }

            // Check if user exists
            if (!$user) {
                return false;
            }

            // Check if user account is activated
            if (!$this->isActivated($user)) {
                $this->logAuthenticationAttempt($user, false, 'User not activated');
                return false;
            }

            // Check if the provided password is correct
            if (!$this->verifyPassword($user, $password)) {
                $this->logAuthenticationAttempt($user, false, 'Wrong password');
                return false;
            }

            // Finalize authentication process after all checks passed
            $this->finalizeAuthentication($user, $remember);

            return true; // Login successful
        }

        /**
         * Enables "remember me" functionality by generating a token and setting a cookie.
         * 
         * @param User $user The user to remember.
         */
        private function rememberUser(User $user): void
        {
            // Remove any existing 'remember_me' tokens for the user to prevent token buildup
            $this->tokenManager->removeTokensForUserByType($user, 'remember_me');

            // Generate a new 'remember_me' token
            $tokenDto = $this->tokenManager->generateToken();

            // Retrieve configuration for 'remember_me' token lifetime and cookie name
            $tokenLifetimeDays = $this->getSetting('remember_me_token_lifetime');
            $cookieName = $this->getSetting('remember_me_cookie_name');

            // Calculate the cookie's expiration time based on the token's lifetime
            $cookieExpiry = time() + 60 * 60 * 24 * $tokenLifetimeDays;

            // Persist the new token associated with the user in the database
            $this->tokenManager->saveToken($user, 'remember_me', $tokenDto->selector, $tokenDto->hashedValidator, $tokenLifetimeDays);

            // Set the 'remember_me' cookie in the user's browser with the generated token
            CookieManager::set($cookieName, $tokenDto->token, (int) $cookieExpiry);
        }

        /**
         * Counts failed login attempts by a user within a given time period.
         * 
         * @param User $user The user whose attempts are being counted.
         * @param DateTimeInterface|null $timePeriod The period from which to count.
         * @return int Number of failed attempts.
         */
        public function countFailedAuthenticationAttempts(User $user, ?DateTimeInterface $timePeriod = null): int
        {
            $timePeriod = $timePeriod ?? new DateTime();

            return $user->getAttempts()
                ->filter(fn(Attempt $attempt): bool
                    => !$attempt->getSuccess() && $attempt->getCreatedAt() >= $timePeriod)
                ->count();
        }

        /**
         * Logs the user out by destroying the session and removing any tokens.
         * 
         * @return bool Returns true if logout was successful, false otherwise.
         */
        public function deauthenticate(): bool
        {
            $loggedInUser = $this->getLoggedInUser();
            $rememberMeCookieName = $this->getSetting('remember_me_cookie_name');

            // Remove "remember me" tokens for the logged-in user, if any
            if ($loggedInUser) {
                $this->tokenManager->removeTokensForUserByType($loggedInUser, $rememberMeCookieName);
            }

            // Delete the "remember me" cookie
            CookieManager::delete($rememberMeCookieName);

            // Destroy the session to complete the logout process
            return $this->sessionManagerInterface->destroy();
        }

        /**
         * Deletes all authentication attempts for a given user.
         * 
         * @param User $user The user whose attempts are deleted.
         * @return bool Returns true if deletion was successful, false otherwise.
         */
        public function deleteAuthenticationAttempts(User $user): bool
        {
            $deleteCount = $this->entityManager
                ->getRepository(Attempt::class)
                ->createQueryBuilder('a')
                ->delete()
                ->where('a.user = :user')
                ->setParameter('user', $user)
                ->getQuery()->execute();

            return $deleteCount > 0;
        }

        /**
         * Checks the status of the user's last authentication attempt.
         * 
         * @param User $user The user whose last attempt is checked.
         * @return bool|null True if last attempt was successful, false if failed, null if no attempts exist.
         */
        public function getLastAuthenticationStatus(User $user): ?bool
        {
            return $user->getAttempts()->last()?->getSuccess();
        }

        /**
         * Checks if a user is authenticated via session or "remember me" token.
         * 
         * @return bool True if the user is authenticated, false otherwise.
         */
        public function isAuthenticated(): bool
        {
            // Check for an existing authenticated user session
            if ($this->sessionManagerInterface->has('user')) {
                return true;
            }

            // Attempt to authenticate using a "remember-me" token, if present
            $token = filter_input(INPUT_COOKIE, $this->getSetting('remember_me_cookie_name'), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
            if ($token && $this->tokenManager->isValid($token)) {
                if ($user = $this->findUserByToken($token)) {
                    $this->finalizeAuthentication($user);
                    return true;
                }
            }

            return false;
        }

        /**
         * Finalizes user authentication, setting the session and handling "remember me".
         * 
         * @param User $user The user to finalize authentication for.
         * @param bool $remember If true, enables "remember me" functionality.
         */
        private function finalizeAuthentication(User $user, bool $remember = false): void
        {
            // Regenerate the session to prevent session fixation attacks
            $this->sessionManagerInterface->regenerate();
            // Delete previous failed attempts
            $this->deleteAuthenticationAttempts($user);
            // Log successful authentication attempt
            $this->logAuthenticationAttempt($user, true);
            // Store the user entity in the session
            $this->sessionManagerInterface->set('user', $user->getId());

            if ($remember) {
                $this->rememberUser($user);
            }
        }

        /**
         * Finds a user by a "remember me" token.
         * 
         * @param string $token The "remember me" token.
         * @return ?User Returns the user if the token is valid, otherwise null.
         */
        private function findUserByToken(string $token): ?User
        {
            // Attempt to parse the token to extract the selector component.
            [$selector] = $this->tokenManager->parseToken($token);

            // Find the token entity by its selector.
            $tokenEntity = $this->entityManager->getRepository(Token::class)->findOneBy(['selector' => $selector]);

            // Return the associated User entity if the token is found, null otherwise.
            return $tokenEntity?->getUser();
        }

        /**
         * Lists all authentication attempts for a user.
         * 
         * @param User $user The user whose attempts are listed.
         * @return Attempt[] Array of attempts.
         */
        public function listAuthenticationAttempts(User $user): array
        {
            return $user->getAttempts()->toArray();
        }

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
        public function logAuthenticationAttempt(User $user, bool $success, ?string $reason = null, ?string $ipAddress = null, ?string $userAgent = null): bool
        {
            $attempt = (new Attempt)
                ->setUser($user)
                ->setSuccess($success)
                ->setReason($reason)
                ->setIpAddress($ipAddress ?: Utils::IP())
                ->setUserAgent($userAgent ?: $_SERVER['HTTP_USER_AGENT']);

            $this->entityManager->persist($attempt);
            $this->entityManager->flush();

            return $this->entityManager->getRepository(Attempt::class)->find($attempt) !== null;
        }

        /**
         * Activates a user account, enabling access.
         * 
         * @param User $user The user to activate.
         */
        public function activateAccount(User $user): void
        {
            $user->setIsActivated(true);
            $this->entityManager->flush();
        }

        /**
         * Deactivates a user account, disabling access.
         * 
         * @param User $user The user to deactivate.
         */
        public function deactivateAccount(User $user): void
        {
            $user->setIsActivated(false);
            $this->entityManager->flush();
        }

        /**
         * Checks if a user's account is activated.
         * 
         * @param User $user The user to check.
         * @return bool True if activated, false otherwise.
         */
        public function isActivated(User $user): bool
        {
            return $user->getIsActivated();
        }

        /**
         * Checks if a user's account is locked.
         * 
         * @param User $user The user to check.
         * @return bool True if locked, false otherwise.
         */
        public function isLocked(User $user): bool
        {
            return $user->getIsLocked();
        }

        /**
         * Locks a user account, preventing login.
         * 
         * @param User $user The user to lock.
         */
        public function lockAccount(User $user): void
        {
            $user->setIsLocked(true);
            $this->entityManager->flush();
        }

        /**
         * Unlocks a user account, allowing login.
         * 
         * @param User $user The user to unlock.
         */
        public function unlockAccount(User $user): void
        {
            $user->setIsLocked(false);
            $this->entityManager->flush();
        }

        /**
         * Generates a unique username based on the user's first name and last initial.
         * 
         * @param string $firstName The user's first name.
         * @param string $lastName The user's last name.
         * @return string The generated username.
         * @throws UsernameIncrementException If incrementing usernames is not allowed.
         */
        private function generateUserName(string $firstName, string $lastName): string
        {
            $usernameBase = sprintf('%s.%s', ucfirst($firstName), ucfirst(substr($lastName, 0, 1)));

            // Retrieve users with usernames starting with the base username
            $existingUsernames = array_map(fn(User $user): string
                => $user->getUserName(), $this->entityManager->getRepository(User::class)->findAll());

            // Filter usernames to find those that match the pattern
            $matchingUsernames = array_filter($existingUsernames, fn(string $username): bool
                => str_starts_with($username, $usernameBase));

            // Count matching usernames to determine the new username's suffix
            $countMatchingUsernames = count($matchingUsernames);

            // If there are matching usernames, append the count + 1 to the base username
            if ($countMatchingUsernames > 0) {
                if (!$this->getSetting('allow_username_increment')) {
                    throw new UsernameIncrementException(
                        sprintf("Incremented usernames are not permitted. Unable to create a unique username based on '%s'.", $usernameBase)
                    );
                }
                return $usernameBase . ($countMatchingUsernames + 1);
            }

            // If there are no matching usernames, return the base username
            return $usernameBase;
        }

        /**
         * Fetches the currently logged-in user.
         * 
         * @return ?User Returns the User if logged in, otherwise null.
         */
        public function getLoggedInUser(): ?User
        {
            // Check if the user is authenticated
            if (!$this->isAuthenticated()) {
                return null;
            }

            // Retrieve the user ID stored in the session
            $userId = $this->sessionManagerInterface->get('user');

            // Fetch and return the User entity associated with the logged-in user's ID
            return $this->entityManager
                ->getRepository(User::class)
                ->find($userId);
        }

        /**
         * Updates a user's password.
         * 
         * @param User $user The user whose password is updated.
         * @param string $newPassword The new password to set.
         */
        private function changePassword(User $user, string $newPassword): void
        {
            $user->setPassword($this->hashPassword($newPassword));
            $this->entityManager->flush();
        }

        /**
         * Hashes a plaintext password for secure storage.
         * 
         * @param string $password The plaintext password.
         * @return string The hashed password.
         */
        public function hashPassword(string $password): string
        {
            return password_hash($password, PASSWORD_DEFAULT, ["cost" => self::PASSWORD_COST]);
        }

        /**
         * Verifies a plaintext password against a stored hashed password.
         * 
         * @param User $user The user whose password is being verified.
         * @param string $password The plaintext password to verify.
         * @return bool True if the password is correct, false otherwise.
         */
        private function verifyPassword(User $user, string $password): bool
        {
            $hashedPassword = $user->getPassword();

            // Check if the password hash matches the current hashing algorithm and parameters
            // and rehash if necessary. This ensures the security of stored passwords remains up-to-date.
            if (password_needs_rehash($hashedPassword, PASSWORD_DEFAULT, ["cost" => self::PASSWORD_COST])) {
                $this->changePassword($user, $hashedPassword);
            }
            return password_verify($password, $hashedPassword);
        }

        /**
         * Fetches a user by their username.
         * 
         * @param string $username The username to search for.
         * @return ?User The User entity, or null if not found.
         */
        public function getUserByUsername(string $username): ?User
        {
            return $this->entityManager->getRepository(User::class)->findOneBy(['username' => $username]);
        }

        /**
         * Lists all registered users.
         * 
         * @return User[] Array of all User entities.
         */
        public function listAllRegistredUsers(): array
        {
            return $this->entityManager->getRepository(User::class)->findAll();
        }

        /**
         * Lists all roles in the system.
         * 
         * @return Role[] Array of all Role entities.
         */
        public function listAllRoles(): array
        {
            return $this->entityManager->getRepository(Role::class)->findAll();
        }

        /**
         * Retrieves a system setting by key.
         * 
         * @param string $key The key for the setting.
         * @return mixed The setting value.
         */
        private function getSetting(string $key): mixed
        {
            return $this->settingsManager->get($key)?->getValue();
        }











        /**
         * Generates a password reset token and triggers an email callback.
         *
         * @param User $user The email of the user requesting the password reset.
         * @param callable $emailCallback A callback function to send the reset email (e.g., sendEmail($user, $token)).
         * @return bool Returns true if the reset token is generated and email sent, false otherwise.
         */
        public function requestPasswordReset(User $user, callable $emailCallback): bool
        {
            $user = $this->entityManager->getRepository(User::class)->find($user);

            if (!$user) {
                throw new EmailNotValidException("No user found with this email.");
            }

            // Generate new password reset token
            $tokenDto = $this->tokenManager->generateToken();

            // Save the reset token
            $this->tokenManager->saveToken($user, 'password_reset', $tokenDto->selector, $tokenDto->hashedValidator, $this->getSetting('password_reset_token_lifetime'));

            // Execute the email callback function
            $emailCallback($user, $tokenDto->selector, $tokenDto->plainValidator);

            return true;
        }

        /**
         * Resets the user's password after verifying the token.
         *
         * @param string $selector The token selector from the reset link.
         * @param string $validator The token validator from the reset link.
         * @param string $newPassword The new password to be set.
         * @return bool Returns true if the password is successfully reset, false otherwise.
         */
        public function resetPassword(string $selector, string $validator, string $newPassword): bool
        {
            $tokenEntity = $this->tokenManager->getTokenBySelector($selector);

            if ($tokenEntity && $this->tokenManager->isValid("$selector:$validator")) {
                $user = $tokenEntity->getUser();

                // Update password
                $this->changePassword($user, $newPassword);

                // Remove the reset token
                $this->tokenManager->removeTokensForUserByType($user, 'password_reset');

                return true;
            }

            return false;
        }

        /**
         * Verifies a user's account using a token.
         *
         * @param string $selector The token selector from the verification link.
         * @param string $validator The token validator from the verification link.
         * @return bool Returns true if the account is successfully verified, false otherwise.
         */
        public function verifyAccount(string $selector, string $validator): bool
        {
            $tokenEntity = $this->tokenManager->getTokenBySelector($selector);

            if ($tokenEntity && $this->tokenManager->isValid("$selector:$validator")) {
                $user = $tokenEntity->getUser();
                $this->activateAccount($user);

                // Remove token after successful verification
                $this->tokenManager->removeToken($tokenEntity);
                return true;
            }

            return false;
        }

        /**
         * Sends a verification email to the user with a token for account activation.
         * 
         * @param User $user The user who needs email verification.
         * @param string $selector The token selector.
         * @param string $validator The token validator.
         * @return bool Returns true if the email was sent successfully, false otherwise.
         */
        public function sendEmailVerification(User $user, string $selector, string $validator): bool
        {
            // Retrieve the user's email address
            $email = $user->getEmail();

            // Set email subject and body
            $subject = 'Please activate your account';
            $message = <<<MESSAGE
                Hi,

                Please click the following link to activate your account:
                https://{$_SERVER['HTTP_HOST']}/activate-account.php?userId={$user->getUserName()}&selector=$selector&validator=$validator
                MESSAGE;

            // Send the email
            return mail($email, $subject, nl2br($message), "From:no-reply@email.com");
        }
    }
}
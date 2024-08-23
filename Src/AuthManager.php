<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTime;
    use DateTimeInterface;
    use Doctrine\ORM\EntityManager;
    use Temant\AuthManager\Config\ConfigManagerInterface;
    use Temant\AuthManager\Entity\Attempt;
    use Temant\AuthManager\Entity\Role;
    use Temant\AuthManager\Entity\Token;
    use Temant\AuthManager\Entity\User;
    use Temant\AuthManager\Exceptions\EmailNotValidException;
    use Temant\AuthManager\Exceptions\RoleNotFoundException;
    use Temant\AuthManager\Exceptions\UsernameIncrementException;
    use Temant\AuthManager\Exceptions\WeakPasswordException;
    use Temant\AuthManager\Utils\Utils;
    use Temant\CookieManager\CookieManager;
    use Temant\SessionManager\SessionManagerInterface;

    final class AuthManager implements AuthManagerInterface
    {
        /**
         * Sets the bcrypt password hashing cost.
         * Increasing this value enhances security by making the hashing process slower,
         * thereby reducing vulnerability to brute force attacks.
         * Choose a value based on the application's performance and security requirements.
         */
        private const PASSWORD_COST = 12;

        /**
         * @param SessionManagerInterface $session
         * @param ConfigManagerInterface $configManager
         * @param TokenManager $tokenManager
         */
        public function __construct(
            private readonly EntityManager $entityManager,
            private readonly SessionManagerInterface $sessionManagerInterface,
            private readonly ConfigManagerInterface $configManager,
            private readonly TokenManager $tokenManager
        ) {
        }

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
         * @return bool Returns true if the user is successfully registered, false otherwise.
         *              for the provided data or an issue with inserting the new record into the database.
         *
         * @throws RoleNotFoundException When the specified user role ID is not found in the database.
         * @throws WeakPasswordException If the password is not matching the recommended settings
         * @throws EmailNotValidException When the Email is not a valid email address
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        public function registerUser(string $firstName, string $lastName, int $roleId, string $email, string $password): bool
        {
            // Generate a username based on the provided first and last name
            $username = $this->generateUserName($firstName, $lastName);

            // Password validation checks
            $validatedPassword = $this->validatePassword($password);

            // Role ID validation checks
            $validatedRole = $this->validateRole($roleId);

            // Email validation checks
            $validatedEmail = $this->validateEmail($email);

            // Create a new User entity and set its properties
            $newUser = (new User)
                ->setUserName($username)
                ->setFirstName($firstName)
                ->setLastName($lastName)
                ->setEmail($validatedEmail)
                ->setPassword($validatedPassword)
                ->setIsActivated(false)
                ->setIsLocked(false)
                ->setRole($validatedRole);

            // Persist the new User entity to the database
            $this->entityManager->persist($newUser);
            $this->entityManager->flush();

            // Additional logic for email verification, etc.
            if ($this->configManager->get('mail_verify') === 'enabled') {
                [$selector, $validator] = $this->tokenManager->generateToken();

                $this->tokenManager->saveToken($newUser, 'email_activation', $selector, $validator, (int) $this->configManager->get('mail_activation_token_lifetime'));
                $this->sendEmailVerification($newUser, $selector, $validator);
            }

            return true;
        }

        /**
         * Removes a specified user entity from the database. This method is responsible for deleting the user record
         * associated with the provided User object. It calls the EntityManager's remove and flush methods to ensure
         * that changes are persisted to the database. This action is irreversible, and all information related to the
         * user will be permanently deleted from the database.
         *
         * @param User $user The user entity to be removed from the database.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        public function removeUser(User $user): void
        {
            $this->entityManager->remove($user);
            $this->entityManager->flush();
        }

        /**
         * Validates a role against the configured role requirements.
         *
         * @param int $roleId The role ID to validate.
         * @return Role The validated Role Entity
         * @throws RoleNotFoundException When the specified user role ID is not found in the database.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        private function validateRole(int $roleId): Role
        {
            // Retrieve the desired Role entity from the database
            $roleEntity = $this->entityManager->getRepository(Role::class)->find($roleId);

            // Throw an exception if the specified user role is not found
            if (!$roleEntity) {
                throw new RoleNotFoundException;
            }

            // Set the Role on the new User entity
            return $roleEntity;
        }

        /**
         * Validates an email against the configured email requirements.
         *
         * @param string $email Email to validate.
         * @throws EmailNotValidException When the Email is not a valid email address 
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        private function validateEmail(string $email): string
        {
            if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return $email;
            }
            throw new EmailNotValidException;
        }

        /**
         * Validates a password against the configured password requirements.
         *
         * @param string $password The password to validate.
         * @return string The securely hashed password, suitable for storage in the database.
         * 
         * @throws WeakPasswordException If the password is not matching the recommended settings
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        private function validatePassword(string $password): string
        {
            // Check minimum length requirem
            if (!is_null($this->configManager->get('password_min_length'))) {
                if (strlen($password) < $this->configManager->getInteger('password_min_length')) {
                    throw new WeakPasswordException("The password is so short");
                }
            }

            // Check if uppercase letter is required
            if (!is_null($this->configManager->get('password_require_uppercase'))) {
                if ($this->configManager->getBoolean('password_require_uppercase') && !preg_match('/[A-Z]/', $password)) {
                    throw new WeakPasswordException("The password must contain at least one uppercase char");
                }
            }

            // Check if lowercase letter is required
            if (!is_null($this->configManager->get('password_require_lowercase'))) {
                if ($this->configManager->getBoolean('password_require_lowercase') && !preg_match('/[a-z]/', $password)) {
                    throw new WeakPasswordException("The password must contain at least one lowercase char");
                }
            }

            // Check if numeric digit is required
            if (!is_null($this->configManager->get('password_require_numeric'))) {
                if ($this->configManager->getBoolean('password_require_numeric') && !preg_match('/\d/', $password)) {
                    throw new WeakPasswordException("The password must contain at least one numeric char");
                }
            }

            // Check if special character is required
            if (!is_null($this->configManager->get('password_require_special'))) {
                if ($this->configManager->getBoolean('password_require_special') && !preg_match('/[^a-zA-Z\d]/', $password)) {
                    throw new WeakPasswordException("The password must contain a special char");
                }
            }

            return $this->hashPassword($password);
        }

        /**
         * Sends an email to the user for email verification.
         * This method typically sends an activation link to the user's email address
         * containing the necessary parameters for account activation.
         *
         * @param User $user The user object whose email address is to be verified.
         * @param string $selector The token selector for email verification.
         * @param string $validator The token validator for email verification.
         * @return bool Returns true if the email is successfully sent, false otherwise.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
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

        /**
         * Authenticates a user by verifying their provided credentials against stored records.
         * This method is typically called during the login process to validate user login attempts.
         *
         * @param string $username The unique identifier for the user, such as username or email address.
         * @param string $password The plaintext password provided by the user for authentication.
         * @param bool $remember Optional. If set to true, the user's session will be remembered across browser sessions.
         * @return bool Returns true if the provided credentials are valid and the user is successfully authenticated, false otherwise.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
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
         * Implements the "remember me" functionality by generating a new persistent login token for a user,
         * securely storing it, and setting a corresponding cookie in the user's browser. This facilitates
         * automatic user authentication on future visits without requiring manual login, enhancing user convenience
         * while maintaining security through token validation.
         *
         * The method handles token generation, existing token cleanup for the user, secure token storage, and
         * cookie setup with appropriate attributes, including the token's expiration.
         *
         * @param User $user The user entity for whom the "remember me" token is being generated and remembered.
         * @return void
         * 
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        private function rememberUser(User $user): void
        {
            // Remove any existing 'remember_me' tokens for the user to prevent token buildup
            $this->tokenManager->removeTokensForUserByType($user, 'remember_me');

            // Generate a new 'remember_me' token
            [$selector, $validator, $token] = $this->tokenManager->generateToken();

            // Retrieve configuration for 'remember_me' token lifetime and cookie name
            $tokenLifetimeDays = $this->configManager->getInteger('remember_me_token_lifetime');
            $cookieName = $this->configManager->get('remember_me_cookie_name');

            // Calculate the cookie's expiration time based on the token's lifetime
            $cookieExpiry = time() + 60 * 60 * 24 * $tokenLifetimeDays;

            // Persist the new token associated with the user in the database
            $this->tokenManager->saveToken($user, 'remember_me', $selector, $validator, $tokenLifetimeDays);

            // Set the 'remember_me' cookie in the user's browser with the generated token
            CookieManager::set($cookieName, $token, $cookieExpiry);
        }

        /**
         * Calculates the quantity of unsuccessful authentication attempts by a specific user within a defined time frame.
         * This functionality is instrumental in enforcing security protocols such as account lockouts after numerous failed login attempts,
         * enhancing the system's resilience against unauthorized access attempts.
         *
         * @param User $user The user entity whose failed authentication attempts are being counted.
         * @param DateTimeInterface|null $timePeriod The starting point in time from which to count failed attempts. Defaults to the current time if not provided.
         * @return int The total count of failed authentication attempts by the user since the specified time.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        public function countFailedAuthenticationAttempts(User $user, ?DateTimeInterface $timePeriod = null): int
        {
            $timePeriod = $timePeriod ?? new DateTime();

            return $user->getAttempts()
                ->filter(fn(Attempt $attempt): bool =>
                    !$attempt->getSuccess() && $attempt->getCreatedAt() >= $timePeriod)
                ->count();
        }

        /**
         * Terminates the current user's session and invalidates any persistent login tokens, effectively logging the user out.
         * This action is a critical part of the logout process, ensuring that subsequent requests require new authentication.
         * The method handles the removal of "remember me" tokens and the deletion of session data, providing a secure and clean
         * logout experience.
         *
         * @return bool True if the logout process completes successfully, including the removal of any persistent tokens and session destruction.
         *              False if any part of the process fails, indicating a potential issue in the logout workflow.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        public function deauthenticate(): bool
        {
            $loggedInUser = $this->getLoggedInUser();
            $rememberMeCookieName = $this->configManager->get('remember_me_cookie_name');

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
         * Clears all recorded authentication attempts for a specified user. This function is instrumental in managing user data privacy
         * and resetting account security settings. By removing all authentication attempt records, it ensures that the user's authentication
         * history is entirely erased, providing a fresh start or aiding in security analysis.
         *
         * @param User $user The user entity whose authentication attempt records are to be purged from the system.
         * @return bool True if all authentication attempt records for the specified user are successfully deleted, indicating a complete
         *              reset of the user's authentication history. False if the deletion process encounters an error, which may require further investigation.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
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
         * Determines the outcome of the most recent authentication attempt made by a given user. This method is useful
         * for understanding a user's last interaction with the authentication system, such as for displaying messages
         * related to their last login attempt or for audit purposes.
         *
         * @param User $user The user entity whose last authentication attempt is being queried.
         * @return bool|null True if the last attempt was successful, false if it was unsuccessful, or null if there are no recorded attempts for the user.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        public function getLastAuthenticationStatus(User $user): ?bool
        {
            // Retrieve the most recent authentication attempt made by the user
            $lastAttempt = $user->getAttempts()->last();

            // Determine the success status of the last attempt, if it exists
            return $lastAttempt?->getSuccess();
        }

        /**
         * Verifies the current user's authentication status, either through an active session or a valid "remember-me" token.
         * This method is central to session management and access control, ensuring that only authenticated users can
         * access protected resources. It also handles session regeneration and clean-up of authentication attempts for
         * users authenticated via "remember-me" tokens.
         *
         * @return bool True if the user is currently authenticated either through a session or a valid "remember-me" token, false otherwise.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        public function isAuthenticated(): bool
        {
            // Check for an existing authenticated user session
            if ($this->sessionManagerInterface->has('user')) {
                return true;
            }

            // Attempt to authenticate using a "remember-me" token, if present
            $token = filter_input(INPUT_COOKIE, $this->configManager->get('remember_me_cookie_name'), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
            if ($token && $this->tokenManager->isValid($token)) {
                if ($user = $this->findUserByToken($token)) {
                    $this->finalizeAuthentication($user);
                    return true;
                }
            }

            return false;
        }

        /**
         * Finalizes the authentication process for a successfully authenticated user.
         * This includes regenerating the session, clearing previous authentication attempts,
         * logging the successful attempt, setting the user session, and handling "remember me" functionality if requested.
         *
         * @param User $user The successfully authenticated user entity.
         * @param bool $remember If true, sets up "remember me" functionality for the user session.
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
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
         * Retrieves a user entity based on a provided "remember-me" token. The method decomposes the token into its
         * constituent parts (selector and validator) and uses these to locate the corresponding token entity in the database.
         * If a matching token is found, the associated user entity is returned. The method ensures that only valid tokens
         * can be used to retrieve user information, enhancing the security of the "remember-me" functionality.
         *
         * @param string $token The "remember-me" token associated with a user's session.
         * @return ?User The User entity associated with the given token if a valid token is found; otherwise, null.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
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
         * Retrieves all authentication attempts made by a specific user. Useful for audit trails, analyzing login patterns,
         * and detecting potential security threats through the examination of failed login attempts. Each attempt includes
         * detailed information such as the timestamp, outcome (success or failure), and originating IP address.
         *
         * @param User $user The user entity whose authentication attempts are being queried.
         * @return Attempt[] An array of Attempt entities associated with the user, providing a historical log of authentication attempts.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        public function listAuthenticationAttempts(User $user): array
        {
            return $user->getAttempts()->toArray();
        }

        /**
         * Records a new authentication attempt for a specified user, capturing critical details such as the attempt's outcome,
         * failure reason (if any), originating IP address, and user agent. This function is vital for maintaining a secure audit
         * trail, monitoring authentication patterns, and facilitating investigations into security incidents.
         *
         * @param User $user The user entity for whom the authentication attempt is being logged.
         * @param bool $success Flag indicating the outcome of the attempt (true for success, false for failure).
         * @param string|null $reason Optional description of why the attempt failed, applicable only for unsuccessful attempts.
         * @param string|null $ipAddress Optional IP address from which the attempt was made, defaults to the current user's IP if not provided.
         * @param string|null $userAgent Optional identifier for the user agent from which the attempt originated, defaults to the current request's user agent if not provided.
         * @return bool Indicating if the attempt was logged successfully.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
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
         * Activates a user's account to enable login and system access.
         * This method is typically invoked post-account creation or during account reactivation processes.
         *
         * @param User $user The user entity whose account is to be activated.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
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
                if (!$this->configManager->getBoolean('allow_username_increment')) {
                    throw new UsernameIncrementException("Username increments are not allowed according to the current configuration settings.");
                }
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
         * @return ?User Returns a User entity object containing the logged-in user's information if authentication is verified,
         *                   otherwise returns null if the user is not authenticated or the user ID does not correspond to an existing record.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         * @see User For the structure of the User entity.
         * @see isAuthenticated() To check the user's authentication status.
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
         * Updates the password for a specified user, typically invoked within account settings or as a security measure.
         * This function sets a new password for the user after hashing it for secure storage. It ensures that users' credentials
         * are kept secure and allows for routine password updates in line with best security practices.
         *
         * @param User $user The user entity whose password is being updated.
         * @param string $newPassword The new password chosen by the user, to be hashed and stored.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
         */
        private function changePassword(User $user, string $newPassword): void
        {
            $user->setPassword($this->hashPassword($newPassword));
            $this->entityManager->flush();
        }

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
        public function hashPassword(string $password): string
        {
            return password_hash($password, PASSWORD_DEFAULT, ["cost" => self::PASSWORD_COST]);
        }

        /**
         * Validates a plaintext password against its corresponding hashed version stored in the database.
         * This is a crucial step in the user authentication process, verifying user-provided credentials during login attempts.
         * Additionally, it checks if the stored hash needs rehashing (e.g., due to a change in the hashing algorithm or parameters)
         * and updates it accordingly, ensuring continued adherence to best security practices.
         *
         * @param User $user The user entity whose password is being verified.
         * @param string $password The plaintext password provided by the user for verification.
         * @return bool True if the plaintext password matches the stored hashed password, false otherwise.
         *
         * @author Emad Almahdi
         * @version 3.0.0
         * @since 2024-02-08
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
         * Sends an email to the user for email verification.
         *
         * @param User $user The user object whose email address is to be verified.
         * @param string $selector The token selector for email verification.
         * @param string $validator The token validator for email verification.
         * @return bool Returns true if the email is successfully sent, false otherwise.
         */
        public function verifyEmail(User $user, string $selector, string $validator): bool
        {
            return true;
        }

        /**
         * Fetches a user's profile information from the database based on their username.
         * This function queries the database for the user entity associated with the provided username.
         * It's primarily used to retrieve a user's profile data or settings based on their username.
         *
         * @param string $username The username of the user whose profile information is to be fetched.
         * @return ?User Returns a User entity object containing the user's information if found,
         *                   otherwise returns null if no user with the provided username exists.
         */
        public function getUserByUsername(string $username): ?User
        {
            return $this->entityManager->getRepository(User::class)->findOneBy(['username' => $username]);
        }

        /**
         * Retrieves a list of all registered users in the system.
         * This method queries the database to fetch all user entities
         * and returns them as an array, providing an overview of all
         * users currently registered in the system.
         * 
         * @return User[] An array of User entities representing all registered users in the system.
         */
        public function listAllRegistredUsers(): array
        {
            return $this->entityManager->getRepository(User::class)->findAll();
        }
    }
}
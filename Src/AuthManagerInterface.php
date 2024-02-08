<?php declare(strict_types=1);

namespace Temant\AuthManager {
    use DateTimeInterface;
    use Exception;
    use Temant\AuthManager\Entity\User;

    interface AuthManagerInterface
    {
        /**
         * Registers a new user in the system with the provided user data.
         *
         * @param string $firstName The first name of the user.
         * @param string $lastName The last name of the user.
         * @param int $role The role ID of the new user.
         * @param string $email The email address of the user.
         * @param string $password The password of the user.
         * @return bool Returns true if the user is successfully registered, false otherwise.
         * @throws Exception When the specified user role is not found in the database.
         */
        public function registerUser(string $firstName, string $lastName, int $role, string $email, string $password): bool;

        /**
         * Sends an email to the user for email verification.
         *
         * @param User $user The user object whose email address is to be verified.
         * @param string $selector The token selector for email verification.
         * @param string $validator The token validator for email verification.
         * @return bool Returns true if the email is successfully sent, false otherwise.
         */
        public function verifyEmail(User $user, string $selector, string $validator): bool;

        /**
         * Authenticates a user by verifying their provided credentials against stored records.
         *
         * @param string $username The unique identifier for the user, such as username or email address.
         * @param string $password The plaintext password provided by the user for authentication.
         * @param bool $remember Optional. If set to true, the user's session will be remembered across browser sessions.
         * @return bool Returns true if the provided credentials are valid and the user is successfully authenticated, false otherwise.
         */
        public function authenticate(string $username, string $password, bool $remember = false): bool;

        /**
         * Calculates the quantity of unsuccessful authentication attempts by a specific user within a defined time frame.
         *
         * @param User $user The user entity whose failed authentication attempts are being counted.
         * @param DateTimeInterface|null $timePeriod The starting point in time from which to count failed attempts.
         * @return int The total count of failed authentication attempts by the user since the specified time.
         */
        public function countFailedAuthenticationAttempts(User $user, ?DateTimeInterface $timePeriod = null): int;

        /**
         * Terminates the current user's session and invalidates any persistent login tokens, effectively logging the user out.
         *
         * @return bool True if the logout process completes successfully, false otherwise.
         */
        public function deauthenticate(): bool;
    }
}
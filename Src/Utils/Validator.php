<?php declare(strict_types=1);

namespace Temant\AuthManager\Utils {

    use Doctrine\ORM\EntityManager;
    use Temant\AuthManager\Entity\RoleEntity;
    use Temant\AuthManager\Exceptions\EmailNotValidException;
    use Temant\AuthManager\Exceptions\RoleNotFoundException;
    use Temant\AuthManager\Exceptions\WeakPasswordException;

    final class Validator
    {
        /**
         * Validate role ID and return the role entity.
         *
         * @param EntityManager $entityManager
         * @param int $roleId
         * @return RoleEntity
         * @throws RoleNotFoundException
         */
        public static function validateRole(EntityManager $entityManager, int $roleId): RoleEntity
        {
            return $entityManager->getRepository(RoleEntity::class)->find($roleId)
                ?? throw new RoleNotFoundException("Role not found.");
        }

        /**
         * Validate email format.
         *
         * @param string $email
         * @return string
         * @throws EmailNotValidException
         */
        public static function validateEmail(string $email): string
        {
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new EmailNotValidException("Invalid email format.");
            }
            return $email;
        }

        /**
         * Validate password strength and requirements.
         *
         * @param string $password
         * @param array<string, null|bool|int> $config Configuration options (key-value pairs).
         * @return string
         * @throws WeakPasswordException
         */
        public static function validatePassword(string $password, array $config): string
        {
            // Check minimum length requirement
            if (isset($config['min_length']) && strlen($password) < $config['min_length']) {
                throw new WeakPasswordException(
                    sprintf("Password must be at least {%d} characters long. You provided {%d} characters", $config['min_length'], strlen($password))
                );
            }

            // Check if uppercase letter is required
            if (isset($config['password_require_uppercase']) && $config['password_require_uppercase'] && !preg_match('/[A-Z]/', $password)) {
                throw new WeakPasswordException("The password must contain at least one uppercase character.");
            }

            // Check if lowercase letter is required
            if (isset($config['password_require_lowercase']) && $config['password_require_lowercase'] && !preg_match('/[a-z]/', $password)) {
                throw new WeakPasswordException("The password must contain at least one lowercase character.");
            }

            // Check if numeric digit is required
            if (isset($config['password_require_numeric']) && $config['password_require_numeric'] && !preg_match('/\d/', $password)) {
                throw new WeakPasswordException("The password must contain at least one numeric character.");
            }

            // Check if special character is required
            if (isset($config['password_require_special']) && $config['password_require_special'] && !preg_match('/[\W_]/', $password)) {
                throw new WeakPasswordException("The password must contain at least one special character.");
            }
            return $password;
        }
    }
}
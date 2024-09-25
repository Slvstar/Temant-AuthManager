<?php declare(strict_types=1);

namespace Temant\AuthManager\Tests {

    use Doctrine\ORM\EntityManager;
    use Doctrine\ORM\EntityRepository;
    use PHPUnit\Framework\Attributes\TestWith;
    use PHPUnit\Framework\TestCase;
    use Temant\AuthManager\Entity\RoleEntity;
    use Temant\AuthManager\Exceptions\EmailNotValidException;
    use Temant\AuthManager\Exceptions\RoleNotFoundException;
    use Temant\AuthManager\Exceptions\WeakPasswordException;
    use Temant\AuthManager\Utils\Validator;

    final class ValidatorTest extends TestCase
    {
        private Validator $validator;

        private $entityManager;

        protected function setUp(): void
        {
            $this->entityManager = $this->createMock(EntityManager::class);
        }

        /**
         * {@inheritdoc}
         */
        protected function tearDown(): void
        {
            parent::tearDown();

            unset($this->validator);
        }

        public function testValidateRoleFound(): void
        {
            $role = new RoleEntity();
            $roleRepo = $this->createMock(EntityRepository::class);
            $roleRepo->method('find')->willReturn($role);
            $this->entityManager->method('getRepository')->willReturn($roleRepo);

            $this->assertSame($role, Validator::validateRole($this->entityManager, 1));
        }

        public function testValidateRoleNotFound(): void
        {
            $roleRepo = $this->createMock(EntityRepository::class);
            $roleRepo->method('find')->willReturn(null);
            $this->entityManager->method('getRepository')->willReturn($roleRepo);

            $this->expectException(RoleNotFoundException::class);
            Validator::validateRole($this->entityManager, 1);
        }

        public function testValidateEmail(): void
        {
            $email = "test@example.com";
            $this->assertEquals($email, Validator::validateEmail($email));
        }

        public function testValidateEmailInvalid(): void
        {
            $this->expectException(EmailNotValidException::class);
            Validator::validateEmail("invalid-email");
        }

        public function testValidatePassword(): void
        {
            $password = "Valid123!";
            $config = [
                'min_length' => 8,
                'password_require_uppercase' => true,
                'password_require_lowercase' => true,
                'password_require_numeric' => true,
                'password_require_special' => true
            ];
            $this->assertEquals($password, Validator::validatePassword($password, $config));
        }

        public function testValidatePasswordWithShortLength(): void
        {
            $pasword = "short";
            $passwordLength = 6;
            $this->expectException(WeakPasswordException::class);
            $this->expectExceptionMessage(
                sprintf("Password must be at least {%s} characters long. You provided {%s} characters", $passwordLength, strlen($pasword))
            );
            Validator::validatePassword($pasword, ['min_length' => $passwordLength]);
        }

        public function testValidatePasswordMissingUppercase(): void
        {
            $this->expectException(WeakPasswordException::class);
            $this->expectExceptionMessage("The password must contain at least one uppercase character.");
            Validator::validatePassword("nocaps", ['password_require_uppercase' => true]);
        }

        public function testValidatePasswordMissingLowercase(): void
        {
            $this->expectException(WeakPasswordException::class);
            $this->expectExceptionMessage("The password must contain at least one lowercase character.");
            Validator::validatePassword("NOCAPS123!", ['password_require_lowercase' => true]);
        }

        public function testValidatePasswordMissingNumeric(): void
        {
            $this->expectException(WeakPasswordException::class);
            $this->expectExceptionMessage("The password must contain at least one numeric character.");
            Validator::validatePassword("NoDigits!", ['password_require_numeric' => true]);
        }

        public function testValidatePasswordMissingSpecialChar(): void
        {
            $this->expectException(WeakPasswordException::class);
            $this->expectExceptionMessage("The password must contain at least one special character.");
            Validator::validatePassword("NoSpecials1", ['password_require_special' => true]);
        }

        #[TestWith(["short", ['min_length' => 6], WeakPasswordException::class])]
        #[TestWith(["123missingupper##", ['password_require_uppercase' => true], WeakPasswordException::class])]
        #[TestWith(["NOCAPS123!", ['password_require_lowercase' => true], WeakPasswordException::class])]
        #[TestWith(["NoDigits!", ['password_require_numeric' => true], WeakPasswordException::class])]
        #[TestWith(["NoSpecials1", ['password_require_special' => true], WeakPasswordException::class])]
        public function testValidatePasswordRequirements($password, $config, $expectedException)
        {
            $this->expectException($expectedException);
            Validator::validatePassword($password, $config);
        }
    }
}
<?php

declare(strict_types=1);

namespace Temant\AuthManager\Tests\Services;

use PHPUnit\Framework\TestCase;
use Temant\AuthManager\Services\PasswordService;

final class PasswordServiceTest extends TestCase
{
    public function testHashPassword(): void
    {
        $password = 'SecureP@ssw0rd!';
        $hash = PasswordService::hashPassword($password);
        $this->assertIsString($hash);
        $this->assertNotEquals($password, $hash);
    }

    public function testVerifyPassword(): void
    {
        $password = 'SecureP@ssw0rd!';
        $hash = PasswordService::hashPassword($password);
        $this->assertTrue(PasswordService::verifyPassword($password, $hash));
        $this->assertFalse(PasswordService::verifyPassword('WrongPassword', $hash));
    }
    
    public function testNeedsRehash(): void
    {
        $password = 'SecureP@ssw0rd!';
        $hash = PasswordService::hashPassword($password);
        $this->assertFalse(PasswordService::needsRehash($hash));
        // Simulate a scenario where the hash needs rehashing by using a different algorithm
        $oldHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 8]);
        $this->assertTrue(PasswordService::needsRehash($oldHash));
    }
}
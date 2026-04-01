<?php

declare(strict_types=1);

namespace Temant\AuthManager;

use DateTime;
use DateTimeInterface;
use Doctrine\ORM\EntityManager;
use Temant\AuthManager\Dto\JwtDto;
use Temant\AuthManager\Dto\TwoFactorSetupDto;
use Temant\AuthManager\Entity\AttemptEntity;
use Temant\AuthManager\Entity\PermissionEntity;
use Temant\AuthManager\Entity\RoleEntity;
use Temant\AuthManager\Entity\TokenEntity;
use Temant\AuthManager\Entity\TwoFactorEntity;
use Temant\AuthManager\Entity\UserEntity;
use Temant\AuthManager\Enum\AuthStatus;
use Temant\AuthManager\Exceptions\EmailNotValidException;
use Temant\AuthManager\Exceptions\UsernameIncrementException;
use Temant\AuthManager\Exceptions\WeakPasswordException;
use Temant\AuthManager\Services\JwtService;
use Temant\AuthManager\Services\TwoFactorService;
use Temant\AuthManager\Utils\Validator;
use Temant\CookieManager\CookieManager;
use Temant\SessionManager\SessionManagerInterface;
use Temant\SettingsManager\SettingsManager;

use function count;
use function sprintf;

/**
 * AuthManager orchestrates authentication, authorization, 2FA, JWT, and
 * all related account-management operations.
 *
 * Highlights:
 *  - Session + "remember me" authentication
 *  - TOTP two-factor authentication (RFC 6238) with backup codes
 *  - Stateless JWT authentication (HS256/384/512)
 *  - Multi-role RBAC with hierarchical role inheritance
 *  - Direct per-user permission grants (bypassing roles)
 *  - Rate limiting: auto-blocks after configurable failed-attempt threshold
 *  - IP address and user-agent logging on every attempt
 */
final class AuthManager implements AuthManagerInterface
{
    private const int PASSWORD_COST = 12;

    /** Session key that stores the authenticated user's ID. */
    private const string SESSION_USER = 'user';

    /** Session key used during the REQUIRES_2FA interim state. */
    private const string SESSION_2FA_PENDING_USER    = 'pending_2fa_user';
    private const string SESSION_2FA_PENDING_REMEMBER = 'pending_2fa_remember';

    /** Token type stored when a JWT is revoked. */
    private const string TOKEN_TYPE_JWT_REVOKED = 'jwt_revoked';

    private readonly SettingsManager $settingsManager;
    private readonly TokenManager $tokenManager;
    private readonly TwoFactorService $twoFactorService;
    private ?JwtService $jwtService = null;

    public function __construct(
        private readonly EntityManager $entityManager,
        private readonly SessionManagerInterface $sessionManagerInterface
    ) {
        $this->settingsManager  = new SettingsManager(
            $entityManager,
            'authentication_settings',
            include __DIR__ . '/DefaultSettings.php'
        );
        $this->tokenManager    = new TokenManager($entityManager);
        $this->twoFactorService = new TwoFactorService();
    }

    // ── User registration & removal ───────────────────────────────────────────

    /**
     * {@inheritdoc}
     */
    public function registerUser(
        string $firstName,
        string $lastName,
        string $email,
        string $password,
        ?RoleEntity $role = null
    ): ?UserEntity {
        $username = $this->generateUserName($firstName, $lastName);

        $validatedPassword = Validator::validatePassword($password, [
            'min_length'        => $this->getSetting('password_min_length'),
            'require_uppercase' => $this->getSetting('password_require_uppercase'),
            'require_lowercase' => $this->getSetting('password_require_lowercase'),
            'require_numeric'   => $this->getSetting('password_require_numeric'),
            'require_special'   => $this->getSetting('password_require_special'),
        ]);

        $newUser = (new UserEntity())
            ->setUserName($username)
            ->setFirstName($firstName)
            ->setLastName($lastName)
            ->setEmail(Validator::validateEmail($email))
            ->setPassword($this->hashPassword($validatedPassword))
            ->setIsActivated(false)
            ->setIsLocked(false);

        if ($role !== null) {
            $newUser->addRole($role);
        }

        $this->entityManager->persist($newUser);
        $this->entityManager->flush();

        if ($this->getSetting('mail_verify')) {
            $lifetime = (int) $this->getSetting('mail_activation_token_lifetime');
            $tokenDto = $this->tokenManager->addToken($newUser, 'email_activation', $lifetime);
            if ($tokenDto) {
                $this->sendEmailVerification($newUser, $tokenDto->selector, $tokenDto->plainValidator);
            }
        }

        return $this->entityManager->getRepository(UserEntity::class)->find($newUser->getId());
    }

    public function removeUser(UserEntity $user): void
    {
        $this->entityManager->remove($user);
        $this->entityManager->flush();
    }

    // ── Authentication ────────────────────────────────────────────────────────

    /**
     * {@inheritdoc}
     */
    public function authenticate(string $username, string $password, bool $remember = false): AuthStatus
    {
        $user = filter_var($username, FILTER_VALIDATE_EMAIL)
            ? $this->entityManager->getRepository(UserEntity::class)->findOneBy(['email' => $username])
            : $this->entityManager->getRepository(UserEntity::class)->findOneBy(['username' => $username]);

        if (!$user) {
            return AuthStatus::FAILED;
        }

        // Rate-limit check
        $lockoutWindow  = (int) $this->getSetting('lockout_duration');
        $maxAttempts    = (int) $this->getSetting('max_failed_attempts');
        $windowStart    = (new DateTime())->modify("-{$lockoutWindow} seconds");
        $failedCount    = $this->countFailedAuthenticationAttempts($user, $windowStart);

        if ($failedCount >= $maxAttempts) {
            return AuthStatus::TOO_MANY_ATTEMPTS;
        }

        if (!$this->isActivated($user)) {
            $this->logAuthenticationAttempt($user, false, 'Account not activated', $this->clientIp(), $this->clientUserAgent());
            return AuthStatus::ACCOUNT_INACTIVE;
        }

        if ($this->isLocked($user)) {
            $this->logAuthenticationAttempt($user, false, 'Account locked', $this->clientIp(), $this->clientUserAgent());
            return AuthStatus::ACCOUNT_LOCKED;
        }

        if (!$this->verifyPassword($user, $password)) {
            $this->logAuthenticationAttempt($user, false, 'Wrong password', $this->clientIp(), $this->clientUserAgent());
            return AuthStatus::FAILED;
        }

        // Credentials correct — check whether 2FA is required
        if ($user->isTwoFactorEnabled()) {
            $this->sessionManagerInterface->set(self::SESSION_2FA_PENDING_USER, $user->getId());
            $this->sessionManagerInterface->set(self::SESSION_2FA_PENDING_REMEMBER, $remember);
            return AuthStatus::REQUIRES_2FA;
        }

        $this->finalizeAuthentication($user, $remember);
        return AuthStatus::SUCCESS;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticateWithEmail(string $email): AuthStatus
    {
        $user = $this->entityManager->getRepository(UserEntity::class)->findOneBy(['email' => $email]);

        if (!$user) {
            return AuthStatus::FAILED;
        }

        if (!$this->isActivated($user)) {
            return AuthStatus::ACCOUNT_INACTIVE;
        }

        if ($this->isLocked($user)) {
            return AuthStatus::ACCOUNT_LOCKED;
        }

        $this->finalizeAuthentication($user);
        return AuthStatus::SUCCESS;
    }

    /**
     * {@inheritdoc}
     */
    public function verifyTwoFactor(string $code): AuthStatus
    {
        $userId = $this->sessionManagerInterface->get(self::SESSION_2FA_PENDING_USER);
        if (!$userId) {
            return AuthStatus::FAILED;
        }

        $user = $this->entityManager->getRepository(UserEntity::class)->find((int) $userId);
        if (!$user || !$user->isTwoFactorEnabled()) {
            return AuthStatus::FAILED;
        }

        if (!$this->twoFactorService->verify($user->getTwoFactor()->getSecret(), $code)) {
            $this->logAuthenticationAttempt($user, false, 'Invalid 2FA code', $this->clientIp(), $this->clientUserAgent());
            return AuthStatus::FAILED;
        }

        $remember = (bool) $this->sessionManagerInterface->get(self::SESSION_2FA_PENDING_REMEMBER);
        $this->sessionManagerInterface->set(self::SESSION_2FA_PENDING_USER, null);
        $this->sessionManagerInterface->set(self::SESSION_2FA_PENDING_REMEMBER, null);

        $this->finalizeAuthentication($user, $remember);
        return AuthStatus::SUCCESS;
    }

    /**
     * {@inheritdoc}
     */
    public function verifyTwoFactorBackupCode(string $code): AuthStatus
    {
        $userId = $this->sessionManagerInterface->get(self::SESSION_2FA_PENDING_USER);
        if (!$userId) {
            return AuthStatus::FAILED;
        }

        $user = $this->entityManager->getRepository(UserEntity::class)->find((int) $userId);
        if (!$user || !$user->isTwoFactorEnabled()) {
            return AuthStatus::FAILED;
        }

        $twoFactor = $user->getTwoFactor();
        $matchedIndex = $this->twoFactorService->verifyBackupCode($code, $twoFactor->getBackupCodes());

        if ($matchedIndex === false) {
            $this->logAuthenticationAttempt($user, false, 'Invalid backup code', $this->clientIp(), $this->clientUserAgent());
            return AuthStatus::FAILED;
        }

        // Consume the used backup code so it cannot be reused
        $codes = $twoFactor->getBackupCodes();
        unset($codes[$matchedIndex]);
        $twoFactor->setBackupCodes(array_values($codes));
        $this->entityManager->flush();

        $remember = (bool) $this->sessionManagerInterface->get(self::SESSION_2FA_PENDING_REMEMBER);
        $this->sessionManagerInterface->set(self::SESSION_2FA_PENDING_USER, null);
        $this->sessionManagerInterface->set(self::SESSION_2FA_PENDING_REMEMBER, null);

        $this->finalizeAuthentication($user, $remember);
        return AuthStatus::SUCCESS;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticateWithJwt(string $token): ?UserEntity
    {
        $dto = $this->validateJwt($token);
        if ($dto === null) {
            return null;
        }
        return $this->getUser($dto->userId);
    }

    /**
     * {@inheritdoc}
     */
    public function deauthenticate(): bool
    {
        $user = $this->getLoggedInUser();
        if ($user) {
            $this->tokenManager->removeTokensForUserByType($user, 'remember_me');
        }

        $cookieName = (string) $this->getSetting('remember_me_cookie_name');
        CookieManager::delete($cookieName);

        return $this->sessionManagerInterface->destroy();
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthenticated(): bool
    {
        if ($this->sessionManagerInterface->has(self::SESSION_USER)) {
            return true;
        }

        $cookieName = (string) $this->getSetting('remember_me_cookie_name');
        $token      = filter_input(INPUT_COOKIE, $cookieName, FILTER_SANITIZE_FULL_SPECIAL_CHARS);

        if ($token && $this->tokenManager->isValid($token)) {
            $user = $this->findUserByToken($token);
            if ($user) {
                $this->finalizeAuthentication($user);
                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getLoggedInUser(): ?UserEntity
    {
        if (!$this->isAuthenticated()) {
            return null;
        }

        $userId = $this->sessionManagerInterface->get(self::SESSION_USER);
        return $this->entityManager->getRepository(UserEntity::class)->find($userId);
    }

    // ── Account status ────────────────────────────────────────────────────────

    public function activateAccount(UserEntity $user): void
    {
        $user->setIsActivated(true);
        $this->entityManager->flush();
    }

    public function deactivateAccount(UserEntity $user): void
    {
        $user->setIsActivated(false);
        $this->entityManager->flush();
    }

    public function isActivated(UserEntity $user): bool
    {
        return $user->getIsActivated();
    }

    public function lockAccount(UserEntity $user): void
    {
        $user->setIsLocked(true);
        $this->entityManager->flush();
    }

    public function unlockAccount(UserEntity $user): void
    {
        $user->setIsLocked(false);
        $this->entityManager->flush();
    }

    public function isLocked(UserEntity $user): bool
    {
        return $user->getIsLocked();
    }

    // ── Password management ───────────────────────────────────────────────────

    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT, ['cost' => self::PASSWORD_COST]);
    }

    public function requestPasswordReset(UserEntity $user, callable $emailCallback): bool
    {
        $user = $this->entityManager->getRepository(UserEntity::class)->find($user->getId());
        if (!$user) {
            throw new EmailNotValidException('No user found with this ID.');
        }

        $lifetime = (int) $this->getSetting('password_reset_token_lifetime');
        $tokenDto = $this->tokenManager->addToken($user, 'password_reset', $lifetime);
        if (!$tokenDto) {
            return false;
        }

        $emailCallback($user, $tokenDto->selector, $tokenDto->plainValidator);
        return true;
    }

    public function resetPassword(string $selector, string $validator, string $newPassword): bool
    {
        $tokenEntity = $this->tokenManager->getTokenBySelector($selector);
        if (!$tokenEntity || !$this->tokenManager->isValid("{$selector}:{$validator}")) {
            return false;
        }

        $user = $tokenEntity->getUser();
        $this->changePassword($user, $newPassword);
        $this->tokenManager->removeTokensForUserByType($user, 'password_reset');

        return true;
    }

    // ── Email verification ────────────────────────────────────────────────────

    public function verifyAccount(string $selector, string $validator): bool
    {
        $tokenEntity = $this->tokenManager->getTokenBySelector($selector);
        if (!$tokenEntity || !$this->tokenManager->isValid("{$selector}:{$validator}")) {
            return false;
        }

        $user = $tokenEntity->getUser();
        $this->activateAccount($user);
        $this->tokenManager->removeToken($tokenEntity);

        return true;
    }

    public function sendEmailVerification(UserEntity $user, string $selector, string $validator): bool
    {
        $subject = 'Please activate your account';
        $host    = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $message = <<<MSG
            Hi {$user->getFirstName()},

            Please click the following link to activate your account:
            https://{$host}/activate-account.php?selector={$selector}&validator={$validator}
            MSG;

        return mail($user->getEmail(), $subject, nl2br($message), 'From:no-reply@' . $host);
    }

    // ── Two-factor authentication ─────────────────────────────────────────────

    /**
     * {@inheritdoc}
     */
    public function setup2FA(UserEntity $user): TwoFactorSetupDto
    {
        // Remove any previous unconfirmed 2FA setup
        $existing = $user->getTwoFactor();
        if ($existing !== null && !$existing->isConfirmed()) {
            $this->entityManager->remove($existing);
            $this->entityManager->flush();
            $user->setTwoFactor(null);
        }

        $secret      = $this->twoFactorService->generateSecret();
        $issuer      = (string) ($this->getSetting('two_factor_issuer') ?? 'AuthManager');
        $backupCount = (int) ($this->getSetting('two_factor_backup_codes_count') ?? 8);

        $backupPairs  = $this->twoFactorService->generateBackupCodes($backupCount);
        $plainCodes   = array_keys($backupPairs);
        $hashedCodes  = array_values($backupPairs);

        $twoFactor = (new TwoFactorEntity())
            ->setUser($user)
            ->setSecret($secret)
            ->setBackupCodes($hashedCodes)
            ->setIsEnabled(false)
            ->setIsConfirmed(false);

        $user->setTwoFactor($twoFactor);
        $this->entityManager->persist($twoFactor);
        $this->entityManager->flush();

        $uri = $this->twoFactorService->getProvisioningUri($secret, $user->getEmail(), $issuer);

        return new TwoFactorSetupDto($secret, $uri, $plainCodes);
    }

    /**
     * {@inheritdoc}
     */
    public function confirm2FA(UserEntity $user, string $code): bool
    {
        $twoFactor = $user->getTwoFactor();
        if ($twoFactor === null || $twoFactor->isConfirmed()) {
            return false;
        }

        if (!$this->twoFactorService->verify($twoFactor->getSecret(), $code)) {
            return false;
        }

        $twoFactor->setIsEnabled(true)->setIsConfirmed(true);
        $this->entityManager->flush();

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function disable2FA(UserEntity $user, string $code): bool
    {
        $twoFactor = $user->getTwoFactor();
        if ($twoFactor === null || !$twoFactor->isEnabled()) {
            return false;
        }

        if (!$this->twoFactorService->verify($twoFactor->getSecret(), $code)) {
            return false;
        }

        $this->entityManager->remove($twoFactor);
        $user->setTwoFactor(null);
        $this->entityManager->flush();

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function regenerateBackupCodes(UserEntity $user, string $code): array|false
    {
        $twoFactor = $user->getTwoFactor();
        if ($twoFactor === null || !$twoFactor->isEnabled()) {
            return false;
        }

        if (!$this->twoFactorService->verify($twoFactor->getSecret(), $code)) {
            return false;
        }

        $backupCount = (int) ($this->getSetting('two_factor_backup_codes_count') ?? 8);
        $backupPairs = $this->twoFactorService->generateBackupCodes($backupCount);

        $twoFactor->setBackupCodes(array_values($backupPairs));
        $this->entityManager->flush();

        return array_keys($backupPairs);
    }

    public function isTwoFactorEnabled(UserEntity $user): bool
    {
        return $user->isTwoFactorEnabled();
    }

    // ── JWT ───────────────────────────────────────────────────────────────────

    /**
     * {@inheritdoc}
     */
    public function generateJwt(UserEntity $user, ?int $expiry = null): string
    {
        return $this->getJwtService()->generate($user, $expiry);
    }

    /**
     * {@inheritdoc}
     */
    public function validateJwt(string $token): ?JwtDto
    {
        $dto = $this->getJwtService()->validate($token);
        if ($dto === null) {
            return null;
        }

        // Check revocation list (JTI stored as selector in the token table)
        if ($this->tokenManager->getTokenBySelector($dto->jti) !== null) {
            return null;
        }

        return $dto;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeJwt(string $token): bool
    {
        $dto = $this->validateJwt($token);
        if ($dto === null) {
            return false;
        }

        $user = $this->getUser($dto->userId);
        if (!$user) {
            return false;
        }

        $expiresAt = (new DateTime())->setTimestamp($dto->expiresAt);

        $revocation = (new TokenEntity())
            ->setUser($user)
            ->setType(self::TOKEN_TYPE_JWT_REVOKED)
            ->setSelector($dto->jti)
            ->setValidator('revoked')
            ->setExpiresAt($expiresAt);

        $this->entityManager->persist($revocation);
        $this->entityManager->flush();

        return true;
    }

    // ── Attempt logging ───────────────────────────────────────────────────────

    public function logAuthenticationAttempt(
        UserEntity $user,
        bool $success,
        ?string $reason = null,
        ?string $ipAddress = null,
        ?string $userAgent = null
    ): bool {
        $attempt = (new AttemptEntity())
            ->setUser($user)
            ->setSuccess($success)
            ->setReason($reason)
            ->setIpAddress($ipAddress)
            ->setUserAgent($userAgent);

        $this->entityManager->persist($attempt);
        $this->entityManager->flush();

        return $this->entityManager->getRepository(AttemptEntity::class)->find($attempt->getId()) !== null;
    }

    public function countFailedAuthenticationAttempts(UserEntity $user, ?DateTimeInterface $since = null): int
    {
        $since ??= new DateTime();

        return $user->getAttempts()
            ->filter(static fn(AttemptEntity $a): bool
                => !$a->getSuccess() && $a->getCreatedAt() >= $since)
            ->count();
    }

    public function listAuthenticationAttempts(UserEntity $user): array
    {
        return $user->getAttempts()->toArray();
    }

    public function deleteAuthenticationAttempts(UserEntity $user): bool
    {
        $deleted = $this->entityManager
            ->getRepository(AttemptEntity::class)
            ->createQueryBuilder('a')
            ->delete()
            ->where('a.user = :user')
            ->setParameter('user', $user)
            ->getQuery()
            ->execute();

        return $deleted > 0;
    }

    public function getLastAuthenticationStatus(UserEntity $user): ?bool
    {
        return $user->getAttempts()->last()?->getSuccess();
    }

    // ── Role / Permission management ──────────────────────────────────────────

    public function createRole(string $name, ?string $description = null, ?RoleEntity $parent = null): RoleEntity
    {
        $role = (new RoleEntity())
            ->setName($name)
            ->setDescription($description)
            ->setParent($parent);

        $this->entityManager->persist($role);
        $this->entityManager->flush();

        return $role;
    }

    public function deleteRole(RoleEntity $role): void
    {
        $this->entityManager->remove($role);
        $this->entityManager->flush();
    }

    public function createPermission(string $name, ?string $description = null): PermissionEntity
    {
        $permission = (new PermissionEntity())
            ->setName($name)
            ->setDescription($description);

        $this->entityManager->persist($permission);
        $this->entityManager->flush();

        return $permission;
    }

    public function deletePermission(PermissionEntity $permission): void
    {
        $this->entityManager->remove($permission);
        $this->entityManager->flush();
    }

    public function assignRole(UserEntity $user, RoleEntity $role): void
    {
        $user->addRole($role);
        $this->entityManager->flush();
    }

    public function removeRoleFromUser(UserEntity $user, RoleEntity $role): void
    {
        $user->removeRole($role);
        $this->entityManager->flush();
    }

    public function assignDirectPermission(UserEntity $user, PermissionEntity $permission): void
    {
        $user->addDirectPermission($permission);
        $this->entityManager->flush();
    }

    public function removeDirectPermission(UserEntity $user, PermissionEntity $permission): void
    {
        $user->removeDirectPermission($permission);
        $this->entityManager->flush();
    }

    public function addPermissionToRole(RoleEntity $role, PermissionEntity $permission): void
    {
        $role->addPermission($permission);
        $this->entityManager->flush();
    }

    public function removePermissionFromRole(RoleEntity $role, PermissionEntity $permission): void
    {
        $role->removePermission($permission);
        $this->entityManager->flush();
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public function getUser(int $id): ?UserEntity
    {
        return $this->entityManager->getRepository(UserEntity::class)->find($id);
    }

    public function getUserByUsername(string $username): ?UserEntity
    {
        return $this->entityManager->getRepository(UserEntity::class)->findOneBy(['username' => $username]);
    }

    public function getUserByEmail(string $email): ?UserEntity
    {
        return $this->entityManager->getRepository(UserEntity::class)->findOneBy(['email' => $email]);
    }

    public function listAllRegistredUsers(): array
    {
        return $this->entityManager->getRepository(UserEntity::class)->findAll();
    }

    public function listAllRoles(): array
    {
        return $this->entityManager->getRepository(RoleEntity::class)->findAll();
    }

    /**
     * Checks if a user has a permission — including global permissions
     * that apply to all authenticated users regardless of assignment.
     */
    public function userHasPermission(UserEntity $user, string $permissionName): bool
    {
        // 1. Check direct + role-based permissions on the entity
        if ($user->hasPermission($permissionName)) {
            return true;
        }

        // 2. Check if the permission is marked as global (applies to everyone)
        $perm = $this->entityManager->getRepository(PermissionEntity::class)
            ->findOneBy(['name' => $permissionName, 'isGlobal' => true]);

        return $perm !== null;
    }

    public function listAllPermissions(): array
    {
        return $this->entityManager->getRepository(PermissionEntity::class)->findAll();
    }

    // ── Settings ──────────────────────────────────────────────────────────────

    public function listSetting(): array
    {
        return $this->settingsManager->all();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private function getSetting(string $key): mixed
    {
        return $this->settingsManager->get($key)?->getValue();
    }

    /**
     * Finalizes a successful authentication: regenerates the session, clears failed
     * attempts, logs success, stores the user ID, and optionally sets a remember-me token.
     */
    private function finalizeAuthentication(UserEntity $user, bool $remember = false): void
    {
        $this->sessionManagerInterface->regenerate();
        $this->deleteAuthenticationAttempts($user);
        $this->logAuthenticationAttempt($user, true, null, $this->clientIp(), $this->clientUserAgent());
        $this->sessionManagerInterface->set(self::SESSION_USER, $user->getId());

        if ($remember) {
            $this->rememberUser($user);
        }
    }

    private function rememberUser(UserEntity $user): void
    {
        $this->tokenManager->removeTokensForUserByType($user, 'remember_me');

        $lifetime   = (int) $this->getSetting('remember_me_token_lifetime');
        $cookieName = (string) $this->getSetting('remember_me_cookie_name');
        $expiresAt  = (new DateTime())->modify("+{$lifetime} seconds");
        $tokenDto   = $this->tokenManager->addToken($user, 'remember_me', $expiresAt);

        if ($tokenDto) {
            CookieManager::set($cookieName, $tokenDto->token, $expiresAt->getTimestamp());
        }
    }

    private function verifyPassword(UserEntity $user, string $password): bool
    {
        $hash = $user->getPassword();

        if (!password_verify($password, $hash)) {
            return false;
        }

        if (password_needs_rehash($hash, PASSWORD_DEFAULT, ['cost' => self::PASSWORD_COST])) {
            $this->changePassword($user, $password);
        }

        return true;
    }

    private function changePassword(UserEntity $user, string $newPassword): void
    {
        $user->setPassword($this->hashPassword($newPassword));
        $this->entityManager->flush();
    }

    private function findUserByToken(string $token): ?UserEntity
    {
        $parsed = $this->tokenManager->parseToken($token);
        if (!$parsed) {
            return null;
        }
        [$selector] = $parsed;
        $tokenEntity = $this->entityManager->getRepository(TokenEntity::class)->findOneBy(['selector' => $selector]);
        return $tokenEntity?->getUser();
    }

    /**
     * @inheritDoc
     */
    public function generateUserName(string $firstName, string $lastName): string
    {
        $base      = sprintf('%s.%s', ucfirst($firstName), ucfirst(substr($lastName, 0, 1)));
        $all       = array_map(
            static fn(UserEntity $u): string => $u->getUserName(),
            $this->entityManager->getRepository(UserEntity::class)->findAll()
        );
        $matching  = array_filter($all, static fn(string $u): bool => str_starts_with($u, $base));
        $count     = count($matching);

        if ($count > 0) {
            if (!$this->getSetting('allow_username_increment')) {
                throw new UsernameIncrementException(
                    sprintf("Username increment is disabled; cannot create unique username from '%s'.", $base)
                );
            }
            return $base . ($count + 1);
        }

        return $base;
    }

    /**
     * Returns a lazily-initialised JwtService using settings for the secret/algorithm/expiry.
     *
     * @throws \RuntimeException If jwt_secret has not been configured.
     */
    private function getJwtService(): JwtService
    {
        if ($this->jwtService === null) {
            $secret = (string) $this->getSetting('jwt_secret');
            if (empty($secret)) {
                throw new \RuntimeException(
                    'JWT secret is not configured. Set "jwt_secret" in your AuthManager settings.'
                );
            }
            $this->jwtService = new JwtService(
                $secret,
                (string) ($this->getSetting('jwt_algorithm') ?? 'HS256'),
                (int)   ($this->getSetting('jwt_expiry')    ?? 3600)
            );
        }
        return $this->jwtService;
    }

    /** Returns the client's IP address from common headers, or null in CLI context. */
    private function clientIp(): ?string
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        }
        return $_SERVER['REMOTE_ADDR'] ?? null;
    }

    /** Returns the client's User-Agent string, or null in CLI context. */
    private function clientUserAgent(): ?string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? null;
    }
}

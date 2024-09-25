<?php declare(strict_types=1);
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Temant\AuthManager\AuthManager;
use Temant\AuthManager\Entity\UserEntity;
use Temant\AuthManager\TokenManager;
use Temant\SessionManager\SessionManager;

require_once __DIR__ . "/vendor/autoload.php";

date_default_timezone_set('Europe/Stockholm');

$config = ORMSetup::createAttributeMetadataConfiguration(
    paths: [__DIR__],
    isDevMode: false
);

$config->setAutoGenerateProxyClasses(true);

// configuring the database connection
$connection = DriverManager::getConnection([
    'driver' => 'pdo_mysql',
    'user' => 'root',
    'password' => 'root',
    'dbname' => 'intradb',
], $config);

// obtaining the entity manager
$entityManager = new EntityManager($connection, $config);

$sessionManager = new SessionManager();

$sessionManager->setName('MY_CUSTOM_SESSION');
$sessionManager->start();

$authManager = new AuthManager($entityManager, $sessionManager);
$user = $authManager->getUserByUsername('Emad.A29');

$tokenManager = new TokenManager($entityManager);

dd($tokenManager->addToken($user, 'TEST_TSTTSTST', (new DateTime())->modify('+2 days')));

if ($token) {
    dd($token->isValid());
}
dd();

$emailCallback = function (UserEntity $user, string $selector, string $validator) {
    $resetLink = "https://{$_SERVER['HTTP_HOST']}/reset-password.php?selector=$selector&validator=$validator";
    $email = $user->getEmail();
    $subject = 'Password Reset Request';

    $message = <<<MESSAGE
        Hi {$user->getFirstName()},
        
        We received a request to reset your password. You can reset it by clicking the link below:
        $resetLink
        
        If you did not request this, please ignore this email.
    MESSAGE;

    // Send the email using PHP's mail() or any other mailing service
    return mail($email, $subject, nl2br($message), "From:no-reply@yourwebsite.com");
};

$user = $authManager->getUserByUsername('Emad.A29');
$authManager->requestPasswordReset($user, $emailCallback);

dd($authManager->authenticate('Emad.A29', '123'));

if ($user) {
    dd($user);
    // Optionally redirect or perform other actions
} else {
    dd("Registration failed.");
}

dd($emad->hasPermission('View Dashboard'));
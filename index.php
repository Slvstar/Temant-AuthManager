<?php declare(strict_types=1);
use Temant\AuthManager\AuthManager;
use Temant\AuthManager\Entity\UserEntity;
use Temant\AuthManager\TokenManager;
use Temant\SessionManager\SessionManager;

require_once __DIR__ . "/vendor/autoload.php";

// obtaining the entity manager
$entityManager = require __DIR__ . "/em.php";

$sessionManager = new SessionManager();

$sessionManager->setName('MY_CUSTOM_SESSION');
$sessionManager->start();

$authManager = new AuthManager($entityManager, $sessionManager);
$user = $authManager->getUserByUsername('Emad.A');

dd($authManager->authenticate('Emad.A', 'Slvstar123', true));

$tokenManager = new TokenManager($entityManager);

dd($tokenManager->addToken($user, 'TEST_TSTTSTST', (new DateTimeImmutable())->modify('+2 days')));

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


if ($user) {
    dd($user);
    // Optionally redirect or perform other actions
} else {
    dd("Registration failed.");
}

dd($emad->hasPermission('View Dashboard'));
<?php declare(strict_types=1);
use Temant\AuthManager\AuthManager;
use Temant\SessionManager\SessionManager;

require_once __DIR__ . "/vendor/autoload.php";

$entityManager = require __DIR__ . "/em.php";

$sessionManager = new SessionManager();

$authManager = new AuthManager($entityManager, $sessionManager);

$selector = $_GET['selector'] ?? null;
$validator = $_GET['validator'] ?? null;


if ($selector && $validator) {

    if ($authManager->resetPassword($selector, $validator, "123")) {
        echo "Password has been reset successfully!";
    } else {
        echo "Invalid or expired token. Please request a new password reset.";
    }
} else {
    echo "Invalid request.";
}

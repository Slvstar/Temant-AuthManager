<?php declare(strict_types=1);
use Temant\AuthManager\AuthManager;
use Temant\SessionManager\SessionManager;

require_once __DIR__ . "/vendor/autoload.php";
$entityManager = require __DIR__ . "/em.php";

$sessionManager = new SessionManager();

$authManager = new AuthManager($entityManager, $sessionManager);


// Retrieve the 'selector' and 'token' (validator) from the URL
$selector = $_GET['selector'] ?? null;
$validator = $_GET['validator'] ?? null;

if (!$selector || !$validator) {
    echo "Invalid request.";
    exit;
}

// Verify the account using the selector and token
if ($authManager->verifyAccount($selector, $validator)) {
    echo "Account successfully activated! You can now log in.";
} else {
    echo "Invalid or expired token. Please request a new verification email.";
}
<?php declare(strict_types=1);
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Temant\AuthManager\AuthManager;
use Temant\SessionManager\SessionManager;

require_once __DIR__ . "/vendor/autoload.php";

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

$authManager = new AuthManager($entityManager, $sessionManager);

$selector = $_GET['selector'] ?? null;
$validator = $_GET['validator'] ?? null;


if ($selector && $validator ) {

    if ($authManager->resetPassword($selector, $validator, "123")) {
        echo "Password has been reset successfully!";
    } else {
        echo "Invalid or expired token. Please request a new password reset.";
    }
} else {
    echo "Invalid request.";
}

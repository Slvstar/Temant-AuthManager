<?php declare(strict_types=1);
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Temant\AuthManager\AuthManager;
use Temant\AuthManager\Entity\User;
use Temant\AuthManager\TokenManager;
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
$tokenManager = new TokenManager($entityManager);

$authManager = new AuthManager($entityManager, $sessionManager, $tokenManager);

$user = $authManager->registerUser('Emad', 'Almahdi', 1, 'emad.storm@gmail.com', "12345");

if ($user) {
    dd($user);
    // Optionally redirect or perform other actions
} else {
    dd("Registration failed.");
}


$emad = $entityManager->getRepository(User::class)->find(1);


dd($emad->hasPermission('View Dashboard'));

$tokenManager = new TokenManager($entityManager);

// [$selector, $hashedValidator, $token] = $tokenManager->generateToken();
//  dump($selector, $hashedValidator, $token);

// $tokenManager->saveToken($emad, 'test_token', $selector, $hashedValidator, 15);


// dump($tokenManager->removeAllTokensForUser($emad));
dump($tokenManager->isValid("889896ac01b3fb0330f7210ffffffffffde0c15de6:7535c9c4cc5e38cb9f07fcb628392af287d950b9c26b55e0f23eb1a01fbaff21"));

/**
  0 => "2fc09f8a2e1123dc0fb51f7138a6f253"
  1 => "$2y$10$PM8YQ7qmgr3S9.z0NqxRjusFiNxx33t8oZRH4gvXJ6JRMuXFwlon."
  2 => "2fc09f8a2e1123dc0fb51f7138a6f253:d42eeef3d60cb82b3a46de3107c507ca9108a8cd07e5d68aa7615888ab48e2bc"
 */
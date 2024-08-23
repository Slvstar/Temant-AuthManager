<?php declare(strict_types=1);
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Temant\AuthManager\Entity\User;
use Temant\AuthManager\TokenManager;

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

$emad = $entityManager->getRepository(User::class)->find(1);

$tokenManager = new TokenManager($entityManager);

[$selector, $hashedValidator, $token] = $tokenManager->generateToken();
// dump($selector, $hashedValidator, $token);

// $tokenManager->saveToken($emad, 'test_token', $selector, $hashedValidator); 


// dd($tokenManager->removeAllTokensForUser($emad));
// dump($tokenManager->isValid('f067615f596dbe2122caffb4e0d4af8b:ab3a0f8fd926e9b8b512e40ec2fe521cd1107d22cda7ffb749ec7242ab63cf71'));
dd($tokenManager->getToken('f067615f596dbe2122caffb4e0d4af8b:ab3a0f8fd926e9b8b512e40ec2fe521cd1107d22cda7ffb749ec7242ab63cf71'));
/**
  0 => "2fc09f8a2e1123dc0fb51f7138a6f253"
  1 => "$2y$10$PM8YQ7qmgr3S9.z0NqxRjusFiNxx33t8oZRH4gvXJ6JRMuXFwlon."
  2 => "2fc09f8a2e1123dc0fb51f7138a6f253:d42eeef3d60cb82b3a46de3107c507ca9108a8cd07e5d68aa7615888ab48e2bc"
 */
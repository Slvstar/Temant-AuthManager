<?php declare(strict_types=1);
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Temant\AuthManager\AuthManager;
use Temant\SessionManager\SessionManager;

include_once __DIR__ . "/../vendor/autoload.php";

// obtaining the entity manager
date_default_timezone_set('Europe/Stockholm');

$config = ORMSetup::createAttributeMetadataConfiguration(
    paths: [__DIR__ . "/../Src/Entity"],
    isDevMode: true
);

$config->setAutoGenerateProxyClasses(false);

// configuring the database connection
$connection = DriverManager::getConnection([
    'driver' => 'pdo_mysql',
    'user' => 'root',
    'password' => 'root',
    'dbname' => 'authy',
], $config);

$entityManager = new EntityManager($connection, $config);

$sessionManager = new SessionManager();

$sessionManager
    ->setName('MY_CUSTOM_SESSION')
    ->start();

$authManager = new AuthManager($entityManager, $sessionManager);
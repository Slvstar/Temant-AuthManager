<?php declare(strict_types=1);
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;

require_once __DIR__ . "/vendor/autoload.php";

date_default_timezone_set('Europe/Stockholm');

$config = ORMSetup::createAttributeMetadataConfiguration(
    paths: [__DIR__ . "/Src/Entity"],
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

return new EntityManager($connection, $config);
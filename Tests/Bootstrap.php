<?php declare(strict_types=1);

use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Temant\AuthManager\AuthManager;
use Temant\SessionManager\SessionManager;

include_once __DIR__ . "/../vendor/autoload.php";

const isDevMode = true;

// Set default timezone
date_default_timezone_set('Europe/Stockholm');

// Define paths
$entityPath = __DIR__ . "/../Src/Entity";
$proxyDir = __DIR__ . "/var/cache/proxies";
$cacheDir = __DIR__ . "/var/cache/doctrine";

// Ensure cache directories exist
if (!file_exists($proxyDir)) {
    mkdir($proxyDir, 0775, true);
}
if (!file_exists($cacheDir)) {
    mkdir($cacheDir, 0775, true);
}

$config = ORMSetup::createAttributeMetadataConfiguration(
    paths: [$entityPath],
    isDevMode: isDevMode,
    proxyDir: $proxyDir
);

// Proxy configuration
$config->setAutoGenerateProxyClasses(isDevMode);
$config->setProxyNamespace('Proxies');

// In production, you might want to use a real cache like APCu or Redis
if (!isDevMode) {
    $cache = new FilesystemAdapter("Temant-AuthManager", directory: $cacheDir);
    $config->setMetadataCache($cache);
    $config->setQueryCache($cache);
    $config->setResultCache($cache);
}

// Database connection
try {
    $connection = DriverManager::getConnection([
        'driver' => 'pdo_mysql',
        'host' => 'localhost',
        'user' => 'root',
        'password' => 'root',
        'dbname' => 'authy',
        'charset' => 'utf8mb4',
        'driverOptions' => [
            PDO::ATTR_STRINGIFY_FETCHES => false,
            PDO::ATTR_EMULATE_PREPARES => false
        ],
    ], $config);

    $entityManager = new EntityManager($connection, $config);
} catch (Throwable $e) {
    die('Database connection failed: ' . $e->getMessage());
}

$sessionManager = new SessionManager();

$sessionManager->setName('MY_CUSTOM_SESSION')
    ->start();

$authManager = new AuthManager($entityManager, $sessionManager);
<?php
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Temant\AuthManager\AuthManager;
use Temant\AuthManager\Config\DatabaseConfig;
use Temant\AuthManager\Entity\Config;
use Temant\AuthManager\Storage\DatabaseStorage;
use Temant\AuthManager\TokenManager;
use Temant\DatabaseManager\DatabaseManager;
use Temant\SessionManager\SessionManager;

include_once __DIR__ . "/vendor/autoload.php";

// Create a simple "default" Doctrine ORM configuration for Attributes
$config = ORMSetup::createAttributeMetadataConfiguration(
    paths: array(__DIR__ . "/Src"),
    isDevMode: true,
);
// configuring the database connection
$connection = DriverManager::getConnection([
    'driver' => 'pdo_mysql',
    'user' => 'intradb',
    'password' => 'Proto!728agt22Ws',
    'dbname' => 'slim',
], $config);

// obtaining the entity manager
$entityManager = new EntityManager($connection, $config);


// dd($entityManager->getRepository(Config::class)->findAll());


// $tokenManager = new TokenManager($entityManager);


// foreach ($tokenManager->listAllTokensForUser('Test') as $key => $value) {
//     dump($value->getCreatedAt());
// }
// exit;
// dd($tokenManager->saveToken('Test', 'Test', 'Test', 'Test'));
// // dd($tokenManager->cleanupExpiredTokens());









$session = new SessionManager;

$session->start([]);

$db = new DatabaseManager(new mysqli('localhost', 'intradb', 'Proto!728agt22Ws', 'slim'));

$auth = new AuthManager($session, $storage = new DatabaseStorage($db), new DatabaseConfig($storage), new TokenManager($entityManager));

// dd($auth->registerUser('Emadov', 'Almahdi', 'emad@almahdi.se', 'Slvstar123@'));
try {
    dump($auth->authenticate('Emad.A', 'Slvstar123@', true));
    //code...
} catch (\Throwable $th) {
    echo $th->getMessage();
}
<?php
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Temant\AuthManager\AuthManager;
use Temant\AuthManager\Config\ConfigManager;
use Temant\AuthManager\Entity\Token;
use Temant\AuthManager\Entity\User;
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
    'dbname' => 'authentication',
], $config);

// obtaining the entity manager
$entityManager = new EntityManager($connection, $config);


$user = $entityManager->getRepository(User::class)->findOneBy(['userId' => "Emad.A"]);

$user->addToken((new Token())
    ->setUser($user)
    ->setType('remember_me')
    ->setSelector(bin2hex(random_bytes(16)))
    ->setValidator(bin2hex(random_bytes(32)))
    ->setExpiresAt((new DateTime())->add(new DateInterval('P' . 1 . 'D'))));
$entityManager->persist($user);
$entityManager->flush();

dd($user->getTokens()->toArray());


// $tokenManager = new TokenManager($entityManager);

// dd($tokenManager->listExpiredTokens());


// dd($tokenManager->saveToken('Test', 'Test', 'Test', 'Test'));
// dd($tokenManager->cleanupExpiredTokens());



$session = new SessionManager;

$session->start([]);

$db = new DatabaseManager(new mysqli('localhost', 'intradb', 'Proto!728agt22Ws', 'authentication'));

$auth = new AuthManager($entityManager, $session, $storage = new DatabaseStorage($db), new ConfigManager($entityManager), new TokenManager($entityManager));

($auth->listAuthenticationAttempts('Emad.A'));

$auth->countFailedAuthenticationAttempts('Emad.A', 111111);
// dd($auth->registerUser('Emadov', 'Almahdi', 'emad@almahdi.se', 'Slvstar123@'));
try {
    var_dump($auth->authenticate('Emad.A', 'Slvstar123@', true));
    var_dump($auth->isAuthenticated());
    var_dump($auth->isActivated('Emad.A'));
    var_dump($auth->isAuthenticated());
    var_dump($auth->deauthenticate());
    var_dump($auth->isAuthenticated());
    //code...
} catch (\Throwable $th) {
    $th->getMessage();
}
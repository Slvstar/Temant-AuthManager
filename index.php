<?php
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Temant\AuthManager\AuthManager;
use Temant\AuthManager\Config\ConfigManager;
use Temant\AuthManager\Entity\Role;
use Temant\AuthManager\Entity\User;
use Temant\AuthManager\TokenManager;
use Temant\DatabaseManager\DatabaseManager;
use Temant\SessionManager\SessionManager;

include_once __DIR__ . '/vendor/autoload.php';

// Create a simple 'default' Doctrine ORM configuration for Attributes
$config = ORMSetup::createAttributeMetadataConfiguration(
    paths: array(__DIR__ . '/Src'),
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


$user = $entityManager->getRepository(User::class)->findOneBy(['username' => 'Emad.A2']);

$user->setRole($entityManager->getRepository(Role::class)->find(2));

dump($entityManager->flush());

dd($user->getRole()->getName());

// $user->addToken((new Token())
//     ->setUser($user)
//     ->setType('remember_me')
//     ->setSelector(bin2hex(random_bytes(16)))
//     ->setValidator(bin2hex(random_bytes(32)))
//     ->setExpiresAt((new DateTime())->add(new DateInterval('P' . 1 . 'D'))));
// $entityManager->persist($user);
// $entityManager->flush();

// dd($user->getTokens()->toArray());



$tokenManager = new TokenManager($entityManager);


//dd($tokenManager->saveToken($user, 'Test', 'Test', 'Test'));
//dd($tokenManager->cleanupExpiredTokens());


$session = new SessionManager;

$session->start([]);

$db = new DatabaseManager(new mysqli('localhost', 'intradb', 'Proto!728agt22Ws', 'authentication'));

$auth = new AuthManager($entityManager, new SessionManager, new ConfigManager($entityManager), new TokenManager($entityManager));

// $auth->removeUser($user);
// dd($auth->getLoggedInUser());

// dd($auth->getLastAuthenticationStatus($user));
// dump($auth->listAuthenticationAttempts($user));
// dd($auth->countFailedAuthenticationAttempts($user, (new DateTime)->sub(new DateInterval('PT30M'))));
// $auth->deactivateAccount($user);
// // dd($auth->getUserObject());

// dd($auth->isAuthenticated());

// dump($auth->listAuthenticationAttempts($user));

// dump($auth->countFailedAuthenticationAttempts($user));

// dd($auth->changePassword($user, 'Slvstar123@'));
$auth->registerUser('Emad', 'Almahdi', 1, 'emad.storm@f.como', 'Slvstar123@');

// dd($auth->authenticate('Emad.A', 'Slvstar123@', true));

// $session->destroy();
// var_dump($auth->isAuthenticated());
// var_dump($auth->isActivated('Emad.A'));
// var_dump($auth->isAuthenticated());
// var_dump($auth->deauthenticate());
// var_dump($auth->isAuthenticated());
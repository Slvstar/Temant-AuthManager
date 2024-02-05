<?php
use Temant\AuthManager\AuthManager;
use Temant\AuthManager\Config\DatabaseConfig;
use Temant\AuthManager\Storage\DatabaseStorage;
use Temant\AuthManager\TokenManager;
use Temant\DatabaseManager\DatabaseManager;
use Temant\SessionManager\SessionManager;

include_once __DIR__ . "/vendor/autoload.php";

$session = new SessionManager;

$session->start([]);

$db = new DatabaseManager(new mysqli('localhost', 'root', '', 'slim'));
$storage = new DatabaseStorage($db);

$auth = new AuthManager($session, $storage, new DatabaseConfig($storage), new TokenManager($storage));
// dump($auth->authenticate('emad.A', 'Slvstar123@', true));
// dump($auth->isAuthenticated('Emad.A'));
dump($auth->getUser('Emad.A')->getGroup());
// dump($auth->deauthenticate());
// dump($auth->getUser('Emad.A'));
// dump($auth->registerUser('Emadov', 'Almahdi', 'emad@almahdi.se', 'Slvstar123@'));
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

$auth = new AuthManager($session, $storage = new DatabaseStorage($db), new DatabaseConfig($storage), new TokenManager($storage));

// dd($auth->registerUser('Emadov', 'Almahdi', 'emad@almahdi.se', 'Slvstar123@'));
dd($auth->authenticate('Emadov.A', 'Slvstar123@', true));
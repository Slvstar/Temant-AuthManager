<?php
use Temant\AuthManager\Auth\Auth;
use Temant\AuthManager\Config\DatabaseConfig;
use Temant\AuthManager\Storage\DatabaseStorage;
use Temant\DatabaseManager\DatabaseManager;
use Temant\SessionManager\Session;

include_once __DIR__ . "/vendor/autoload.php";

$db = new DatabaseManager(new mysqli('localhost', 'root', '', 'slim'));

$auth = new Auth(new Session, $storage = new DatabaseStorage($db), new DatabaseConfig($storage));

// dd($auth->registerUser('Emadov', 'Almahdi', 'emad@almahdi.se', 'Slvstar123@'));
dd($auth->login('emad.A', 'Slvstar123@'));
<?php declare(strict_types=1);

include_once __DIR__ . "/../Bootstrap.php";

if ($authManager->deauthenticate()) {
    exit(header("Location:index.php"));
}
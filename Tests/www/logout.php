<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

$authManager->deauthenticate();
flash('success', 'You have been signed out successfully.');
header('Location: login.php');
exit;

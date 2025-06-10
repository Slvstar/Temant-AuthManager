<?php declare(strict_types=1);

include_once __DIR__ . "/../Bootstrap.php";

if (!$authManager->isAuthenticated()) {
    exit(header('Location: login.php'));
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gray-100 min-h-screen">
    <header class="bg-white shadow p-4 flex justify-between items-center">
        <h1 class="text-xl font-semibold text-gray-800">Dashboard</h1>
        <a href="logout.php" class="text-sm text-red-600 hover:underline">Logout</a>
    </header>

    <main class="p-6">
        <div class="bg-white p-6 rounded-xl shadow">
            <h2 class="text-2xl font-bold text-gray-700 mb-4">
                <?= $authManager->getLoggedInUser()->getFullName() ?>, Welcome to your dashboard
            </h2>
            <p class="text-gray-600">This is a secure area of the application. Customize it as needed.</p>
            <?php dump($authManager->getLoggedInUser()) ?>
        </div>
    </main>
</body>

</html>
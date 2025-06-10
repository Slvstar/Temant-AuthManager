<?php declare(strict_types=1);

include_once __DIR__ . "/../Bootstrap.php";

if (!empty($_POST)) {
    if ($authManager->authenticate($_POST['username'], $_POST['password'], isset($_POST['remember_me']))) {
        exit(header("location: index.php"));
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <form action="" method="post" class="bg-white p-8 rounded-2xl shadow-md w-full max-w-sm space-y-6">
        <h2 class="text-2xl font-semibold text-center text-gray-800">Login</h2>

        <div>
            <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
            <input type="text" name="username" id="username"
                class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none" />
        </div>

        <div>
            <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
            <input type="password" name="password" id="password"
                class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none" />
        </div>

        <div class="flex items-center">
            <input type="checkbox" name="remember_me" id="remember_me"
                class="h-4 w-4 text-blue-600 border-gray-300 rounded">
            <label for="remember_me" class="ml-2 block text-sm text-gray-700">Remember me</label>
        </div>

        <button type="submit"
            class="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition duration-200">
            Login
        </button>
    </form>
</body>

</html>
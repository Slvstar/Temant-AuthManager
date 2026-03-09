<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

use Temant\AuthManager\Enum\AuthStatus;

if ($authManager->isAuthenticated()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember_me']);

    saveOld(['username' => $username]);

    $status = $authManager->authenticate($username, $password, $remember);

    switch ($status) {
        case AuthStatus::SUCCESS:
            flash('success', 'Welcome back!');
            header('Location: dashboard.php');
            exit;

        case AuthStatus::REQUIRES_2FA:
            header('Location: verify-2fa.php');
            exit;

        case AuthStatus::ACCOUNT_INACTIVE:
            $error = 'Your account has not been activated yet. Check your email for a verification link.';
            break;

        case AuthStatus::ACCOUNT_LOCKED:
            $error = 'This account has been locked. Please contact an administrator.';
            break;

        case AuthStatus::TOO_MANY_ATTEMPTS:
            $error = 'Too many failed attempts. Please wait 15 minutes before trying again.';
            break;

        default:
            $error = 'Invalid username or password.';
    }
}

publicPage('Sign In');
?>
<div class="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
  <div class="w-full max-w-md">

    <!-- Logo -->
    <div class="text-center mb-8">
      <div class="inline-flex items-center justify-center w-16 h-16 bg-white/10 backdrop-blur rounded-2xl mb-4 text-3xl">🔐</div>
      <h1 class="text-3xl font-bold text-white">AuthManager</h1>
      <p class="text-blue-200 mt-1 text-sm">Full-Featured Auth Demo</p>
    </div>

    <!-- Card -->
    <div class="bg-white rounded-2xl shadow-2xl p-8 fade-in">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">Sign in to your account</h2>

      <?php if ($error): ?>
        <div class="mb-4 p-4 rounded-xl bg-red-50 border border-red-300 text-red-700 text-sm flex items-start gap-2">
          <span class="font-bold">✗</span><span><?= e($error) ?></span>
        </div>
      <?php endif; ?>

      <form method="POST" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Username or Email</label>
          <input type="text" name="username" value="<?= old('username') ?>"
                 class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition text-sm"
                 placeholder="john.doe or john@example.com" required autofocus />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Password</label>
          <input type="password" name="password"
                 class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition text-sm"
                 placeholder="••••••••" required />
        </div>

        <div class="flex items-center justify-between">
          <label class="flex items-center gap-2 text-sm text-gray-600 cursor-pointer">
            <input type="checkbox" name="remember_me" class="rounded border-gray-300 text-blue-600" />
            Remember me for 30 days
          </label>
          <a href="forgot-password.php" class="text-sm text-blue-600 hover:underline">Forgot password?</a>
        </div>

        <button type="submit"
                class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition shadow-sm">
          Sign In
        </button>
      </form>

      <p class="text-center text-sm text-gray-500 mt-6">
        Don't have an account?
        <a href="register.php" class="text-blue-600 font-medium hover:underline">Create one</a>
      </p>

      <div class="mt-4 pt-4 border-t border-gray-100 text-center">
        <a href="setup.php" class="text-xs text-gray-400 hover:text-gray-600">⚙ Seed demo data</a>
      </div>
    </div>
  </div>
</div>
<?php layoutEnd(); ?>

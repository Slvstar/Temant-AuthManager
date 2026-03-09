<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

use Temant\AuthManager\Exceptions\WeakPasswordException;

$selector  = $_GET['selector']  ?? ($_POST['selector']  ?? '');
$validator = $_GET['validator'] ?? ($_POST['validator'] ?? '');

$success = false;
$error   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm']  ?? '';

    if ($password !== $confirm) {
        $error = 'Passwords do not match.';
    } else {
        try {
            if ($authManager->resetPassword($selector, $validator, $password)) {
                $success = true;
            } else {
                $error = 'Invalid or expired reset token. Please request a new link.';
            }
        } catch (WeakPasswordException $e) {
            $error = 'Password too weak: ' . $e->getMessage();
        }
    }
}

if (!$selector || !$validator) {
    $error = 'Invalid request. Please use the link from your email.';
}

publicPage('Reset Password');
?>
<div class="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
  <div class="w-full max-w-md">

    <div class="text-center mb-8">
      <div class="inline-flex items-center justify-center w-16 h-16 bg-white/10 backdrop-blur rounded-2xl mb-4 text-3xl">🔏</div>
      <h1 class="text-2xl font-bold text-white">Choose New Password</h1>
      <p class="text-blue-200 mt-1 text-sm">Make it strong and unique</p>
    </div>

    <div class="bg-white rounded-2xl shadow-2xl p-8 fade-in">

      <?php if ($success): ?>
        <div class="text-center">
          <div class="text-5xl mb-4">🎉</div>
          <h2 class="text-lg font-semibold text-gray-800 mb-2">Password updated!</h2>
          <p class="text-sm text-gray-500 mb-4">Your password has been reset successfully.</p>
          <a href="login.php"
             class="inline-block px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition">
            Sign In
          </a>
        </div>

      <?php elseif ($error && !$selector): ?>
        <div class="text-center">
          <div class="text-5xl mb-4">❌</div>
          <p class="text-sm text-red-600 mb-4"><?= e($error) ?></p>
          <a href="forgot-password.php" class="text-blue-600 hover:underline text-sm">Request a new link</a>
        </div>

      <?php else: ?>
        <h2 class="text-xl font-semibold text-gray-800 mb-6">Set your new password</h2>

        <?php if ($error): ?>
          <div class="mb-4 p-3 rounded-xl bg-red-50 border border-red-300 text-red-700 text-sm"><?= e($error) ?></div>
        <?php endif; ?>

        <form method="POST" class="space-y-4">
          <input type="hidden" name="selector"  value="<?= e($selector) ?>" />
          <input type="hidden" name="validator" value="<?= e($validator) ?>" />

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">New Password</label>
            <input type="password" name="password" autofocus required
                   class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                   placeholder="Min. 8 chars, upper, lower, number" />
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
            <input type="password" name="confirm" required
                   class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                   placeholder="••••••••" />
          </div>

          <button type="submit"
                  class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition">
            Update Password
          </button>
        </form>
      <?php endif; ?>
    </div>
  </div>
</div>
<?php layoutEnd(); ?>

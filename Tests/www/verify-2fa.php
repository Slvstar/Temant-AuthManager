<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

use Temant\AuthManager\Enum\AuthStatus;

// Must have a pending 2FA session
if (!$sessionManager->has('pending_2fa_user')) {
    header('Location: login.php');
    exit;
}

$error = '';
$mode  = $_GET['mode'] ?? 'totp'; // totp | backup

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = trim($_POST['code'] ?? '');
    $mode = $_POST['mode'] ?? 'totp';

    $status = $mode === 'backup'
        ? $authManager->verifyTwoFactorBackupCode($code)
        : $authManager->verifyTwoFactor($code);

    if ($status === AuthStatus::SUCCESS) {
        flash('success', 'Two-factor authentication verified. Welcome!');
        header('Location: dashboard.php');
        exit;
    }

    $error = $mode === 'backup'
        ? 'Invalid backup code. Please try again.'
        : 'Invalid authentication code. Please try again.';
}

publicPage('Two-Factor Verification');
?>
<div class="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
  <div class="w-full max-w-md">

    <div class="text-center mb-8">
      <div class="inline-flex items-center justify-center w-16 h-16 bg-white/10 backdrop-blur rounded-2xl mb-4 text-4xl">🔒</div>
      <h1 class="text-2xl font-bold text-white">Two-Factor Verification</h1>
      <p class="text-blue-200 mt-1 text-sm">Enter the code from your authenticator app</p>
    </div>

    <div class="bg-white rounded-2xl shadow-2xl p-8 fade-in">

      <?php if ($error): ?>
        <div class="mb-4 p-3 rounded-xl bg-red-50 border border-red-300 text-red-700 text-sm flex items-start gap-2">
          <span class="font-bold">✗</span><span><?= e($error) ?></span>
        </div>
      <?php endif; ?>

      <!-- Tabs -->
      <div class="flex gap-1 mb-6 bg-gray-100 rounded-xl p-1">
        <a href="?mode=totp"
           class="flex-1 text-center py-2 rounded-lg text-sm font-medium transition <?= $mode !== 'backup' ? 'bg-white text-gray-800 shadow-sm' : 'text-gray-500 hover:text-gray-700' ?>">
          📱 Authenticator
        </a>
        <a href="?mode=backup"
           class="flex-1 text-center py-2 rounded-lg text-sm font-medium transition <?= $mode === 'backup' ? 'bg-white text-gray-800 shadow-sm' : 'text-gray-500 hover:text-gray-700' ?>">
          🔑 Backup Code
        </a>
      </div>

      <form method="POST" class="space-y-5">
        <input type="hidden" name="mode" value="<?= e($mode) ?>" />

        <?php if ($mode !== 'backup'): ?>
          <div class="text-center">
            <label class="block text-sm font-medium text-gray-700 mb-3">
              Enter the 6-digit code displayed in your authenticator app
            </label>
            <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}"
                   maxlength="6" autofocus autocomplete="one-time-code"
                   class="w-40 text-center text-2xl tracking-[.3em] font-mono px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
                   placeholder="000000" required />
            <p class="text-xs text-gray-400 mt-2">Code refreshes every 30 seconds</p>
          </div>
        <?php else: ?>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">
              Enter one of your backup codes
            </label>
            <input type="text" name="code" autofocus autocomplete="off"
                   class="w-full font-mono text-center tracking-widest px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm uppercase"
                   placeholder="XXXXXXXXXX" required />
            <p class="text-xs text-gray-400 mt-1">Each backup code can only be used once.</p>
          </div>
        <?php endif; ?>

        <button type="submit"
                class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition">
          Verify &amp; Sign In
        </button>
      </form>

      <div class="mt-4 pt-4 border-t border-gray-100 text-center">
        <a href="login.php" class="text-sm text-gray-500 hover:text-gray-700">← Back to login</a>
      </div>
    </div>
  </div>
</div>
<?php layoutEnd(); ?>

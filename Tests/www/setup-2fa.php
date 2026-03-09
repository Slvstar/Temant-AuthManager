<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

if (!$authManager->isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$setup = $_SESSION['_2fa_setup'] ?? null;
if (!$setup) {
    flash('error', 'No 2FA setup in progress. Please start from Security settings.');
    header('Location: security.php');
    exit;
}

$user  = $authManager->getLoggedInUser();
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = trim($_POST['code'] ?? '');
    if ($authManager->confirm2FA($user, $code)) {
        unset($_SESSION['_2fa_setup']);
        // Show backup codes one time
        $_SESSION['_backup_codes_new'] = $setup['backup'];
        flash('success', '🎉 Two-factor authentication is now active on your account!');
        header('Location: security.php');
        exit;
    }
    $error = 'Invalid code. Please check your authenticator app and try again.';
}

layoutStart('Set Up Two-Factor Authentication');
?>
<div class="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
  <div class="w-full max-w-lg">

    <!-- Steps indicator -->
    <div class="flex items-center justify-center gap-3 mb-8">
      <?php foreach (['Scan QR Code', 'Verify Code', 'Backup Codes'] as $i => $step): ?>
        <?php $active = $i === 1; $done = $i === 0; ?>
        <div class="flex items-center gap-2 <?= $active ? 'text-white' : ($done ? 'text-blue-300' : 'text-blue-500') ?>">
          <div class="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold
                      <?= $active ? 'bg-white text-blue-800' : ($done ? 'bg-blue-400 text-white' : 'bg-blue-700 text-blue-300') ?>">
            <?= $done ? '✓' : ($i + 1) ?>
          </div>
          <span class="text-sm hidden sm:block"><?= $step ?></span>
        </div>
        <?php if ($i < 2): echo '<div class="w-8 h-px bg-blue-600"></div>'; endif; ?>
      <?php endforeach; ?>
    </div>

    <div class="bg-white rounded-2xl shadow-2xl p-8 fade-in">
      <h2 class="text-xl font-semibold text-gray-800 mb-1">Scan the QR code</h2>
      <p class="text-sm text-gray-500 mb-6">
        Open your authenticator app (Google Authenticator, Authy, etc.) and scan this code.
        Then enter the 6-digit verification code below to confirm.
      </p>

      <?php if ($error): ?>
        <div class="mb-4 p-3 rounded-xl bg-red-50 border border-red-300 text-red-700 text-sm flex items-start gap-2">
          <span class="font-bold">✗</span><span><?= e($error) ?></span>
        </div>
      <?php endif; ?>

      <!-- QR code display -->
      <div class="flex flex-col items-center mb-6">
        <div id="qrcode" class="p-3 bg-white border-2 border-gray-200 rounded-2xl shadow-sm mb-3"></div>
        <p class="text-xs text-gray-400">Can't scan? Enter this secret manually:</p>
        <code class="mt-1 px-3 py-1.5 bg-gray-100 rounded-lg text-sm font-mono tracking-widest text-gray-700 select-all">
          <?= e($setup['secret']) ?>
        </code>
      </div>

      <!-- Backup codes preview -->
      <div class="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-xl">
        <p class="text-xs font-semibold text-blue-700 mb-2">🔑 Your backup codes (save these!):</p>
        <div class="grid grid-cols-4 gap-1">
          <?php foreach ($setup['backup'] as $code): ?>
            <span class="font-mono text-xs bg-white border border-blue-100 rounded px-2 py-1 text-center text-gray-700">
              <?= e($code) ?>
            </span>
          <?php endforeach; ?>
        </div>
        <p class="text-xs text-blue-500 mt-2">These will be shown one more time after verification.</p>
      </div>

      <!-- Verification form -->
      <form method="POST">
        <label class="block text-sm font-medium text-gray-700 mb-2">Enter the 6-digit code from your app</label>
        <div class="flex gap-3">
          <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6"
                 autofocus autocomplete="one-time-code"
                 class="flex-1 text-center text-2xl tracking-[.3em] font-mono px-4 py-3 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                 placeholder="000000" required />
          <button type="submit"
                  class="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition">
            Confirm
          </button>
        </div>
      </form>

      <div class="mt-4 text-center">
        <a href="security.php" class="text-sm text-gray-400 hover:text-gray-600">← Cancel setup</a>
      </div>
    </div>
  </div>
</div>

<!-- QR code generator (no CDN dependency — uses canvas via qrcodejs) -->
<script src="https://cdn.jsdelivr.net/gh/davidshimjs/qrcodejs/qrcode.min.js"></script>
<script>
  new QRCode(document.getElementById("qrcode"), {
    text: <?= json_encode($setup['uri']) ?>,
    width: 180,
    height: 180,
    colorDark: "#1e3a5f",
    colorLight: "#ffffff",
    correctLevel: QRCode.CorrectLevel.M
  });
</script>
<?php layoutEnd(); ?>

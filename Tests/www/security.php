<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

authPage('Security & 2FA', $authManager);
$user = $authManager->getLoggedInUser();

// ── Handle form actions ───────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'setup_2fa':
            $dto = $authManager->setup2FA($user);
            // Store DTO data in session to display the QR code page
            $_SESSION['_2fa_setup'] = [
                'secret'  => $dto->secret,
                'uri'     => $dto->provisioningUri,
                'backup'  => $dto->backupCodes,
            ];
            header('Location: setup-2fa.php');
            exit;

        case 'disable_2fa':
            $code = trim($_POST['disable_code'] ?? '');
            if ($authManager->disable2FA($user, $code)) {
                flash('success', 'Two-factor authentication has been disabled.');
            } else {
                flash('error', 'Invalid code. 2FA was not disabled.');
            }
            break;

        case 'regen_backup':
            $code = trim($_POST['regen_code'] ?? '');
            $new  = $authManager->regenerateBackupCodes($user, $code);
            if ($new !== false) {
                $_SESSION['_backup_codes_new'] = $new;
                flash('success', 'New backup codes generated. Save them now — they will not be shown again.');
            } else {
                flash('error', 'Invalid code. Backup codes were not regenerated.');
            }
            break;
    }
    header('Location: security.php');
    exit;
}

$newBackupCodes = $_SESSION['_backup_codes_new'] ?? null;
unset($_SESSION['_backup_codes_new']);

authPage('Security & 2FA', $authManager);
$user = $authManager->getLoggedInUser();
?>
<?= renderFlash() ?>

<!-- 2FA section -->
<div class="max-w-2xl space-y-6">

  <!-- Status card -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <div class="flex items-start justify-between">
      <div class="flex items-center gap-4">
        <div class="w-12 h-12 rounded-2xl <?= $user->isTwoFactorEnabled() ? 'bg-green-100 text-green-600' : 'bg-yellow-100 text-yellow-600' ?> flex items-center justify-center text-2xl">
          <?= $user->isTwoFactorEnabled() ? '🛡️' : '⚠️' ?>
        </div>
        <div>
          <h2 class="text-base font-semibold text-gray-800">Two-Factor Authentication</h2>
          <p class="text-sm text-gray-500 mt-0.5">
            <?= $user->isTwoFactorEnabled()
                ? 'Your account is protected with TOTP-based 2FA.'
                : 'Add an extra layer of security to your account.' ?>
          </p>
        </div>
      </div>
      <?= badge($user->isTwoFactorEnabled(), 'Enabled', 'Disabled') ?>
    </div>

    <?php if ($user->isTwoFactorEnabled()): ?>
      <div class="mt-5 pt-5 border-t border-gray-100 grid grid-cols-1 sm:grid-cols-2 gap-4">

        <!-- Disable 2FA -->
        <form method="POST" onsubmit="return confirm('Disable 2FA on your account?')">
          <input type="hidden" name="action" value="disable_2fa" />
          <label class="block text-sm font-medium text-gray-700 mb-1">Current TOTP code to disable</label>
          <div class="flex gap-2">
            <input type="text" name="disable_code" maxlength="6" inputmode="numeric" placeholder="000000"
                   class="flex-1 px-3 py-2 border border-gray-300 rounded-xl text-sm font-mono focus:ring-2 focus:ring-red-400 outline-none" required />
            <button type="submit"
                    class="px-4 py-2 bg-red-500 hover:bg-red-600 text-white text-sm font-medium rounded-xl transition">
              Disable
            </button>
          </div>
        </form>

        <!-- Regenerate backup codes -->
        <form method="POST">
          <input type="hidden" name="action" value="regen_backup" />
          <label class="block text-sm font-medium text-gray-700 mb-1">TOTP code to regenerate backup codes</label>
          <div class="flex gap-2">
            <input type="text" name="regen_code" maxlength="6" inputmode="numeric" placeholder="000000"
                   class="flex-1 px-3 py-2 border border-gray-300 rounded-xl text-sm font-mono focus:ring-2 focus:ring-blue-400 outline-none" required />
            <button type="submit"
                    class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-xl transition">
              Regenerate
            </button>
          </div>
        </form>
      </div>
    <?php else: ?>
      <form method="POST" class="mt-5 pt-5 border-t border-gray-100">
        <input type="hidden" name="action" value="setup_2fa" />
        <button type="submit"
                class="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm rounded-xl transition">
          Set Up Two-Factor Authentication →
        </button>
      </form>
    <?php endif; ?>
  </div>

  <!-- New backup codes display -->
  <?php if (!empty($newBackupCodes)): ?>
  <div class="bg-yellow-50 border border-yellow-300 rounded-2xl p-6">
    <h3 class="text-base font-semibold text-yellow-800 mb-1 flex items-center gap-2">🔑 New Backup Codes</h3>
    <p class="text-sm text-yellow-700 mb-4">
      Save these codes somewhere safe. Each can only be used once. They will not be shown again.
    </p>
    <div class="grid grid-cols-2 gap-2">
      <?php foreach ($newBackupCodes as $code): ?>
        <div class="font-mono text-sm bg-white border border-yellow-200 rounded-lg px-3 py-2 text-gray-700 tracking-widest">
          <?= e($code) ?>
        </div>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endif; ?>

  <!-- Password section -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">🔏 Change Password</h2>
    <p class="text-sm text-gray-500 mb-4">
      Use the password reset flow to change your password securely.
    </p>
    <a href="forgot-password.php"
       class="inline-block px-5 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 text-sm font-medium rounded-xl transition">
      Request Password Reset Link
    </a>
  </div>

  <!-- Account info -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">ℹ️ Account Status</h2>
    <div class="space-y-2.5 text-sm">
      <?php
      $rows = [
        ['Account activated', badge($user->getIsActivated(), 'Yes', 'No')],
        ['Account locked',    badge(!$user->getIsLocked(), 'No', 'Yes (contact admin)')],
        ['2FA protection',    badge($user->isTwoFactorEnabled(), 'Active', 'Not set up')],
        ['Member since',      e($user->getCreatedAt()->format('F j, Y'))],
        ['Last updated',      e($user->getUpdatedAt()?->format('M j, Y H:i') ?? '—')],
      ];
      foreach ($rows as [$label, $value]):
      ?>
      <div class="flex justify-between items-center py-1.5 border-b border-gray-50 last:border-0">
        <span class="text-gray-500"><?= $label ?></span>
        <span><?= $value ?></span>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
</div>

<?php sidebarEnd(); layoutEnd(); ?>

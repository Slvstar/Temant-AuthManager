<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

$selector  = $_GET['selector']  ?? '';
$validator = $_GET['validator'] ?? '';
$success   = false;
$error     = '';

if ($selector && $validator) {
    if ($authManager->verifyAccount($selector, $validator)) {
        $success = true;
    } else {
        $error = 'Invalid or expired activation link. Please register again or request a new email.';
    }
} else {
    $error = 'Invalid request. Missing activation parameters.';
}

publicPage('Activate Account');
?>
<div class="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
  <div class="w-full max-w-md">
    <div class="bg-white rounded-2xl shadow-2xl p-10 text-center fade-in">

      <?php if ($success): ?>
        <div class="text-6xl mb-4">🎉</div>
        <h1 class="text-2xl font-bold text-gray-800 mb-2">Account Activated!</h1>
        <p class="text-gray-500 text-sm mb-6">
          Your email has been verified and your account is now active.
        </p>
        <a href="login.php"
           class="inline-block px-8 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition">
          Sign In
        </a>
      <?php else: ?>
        <div class="text-6xl mb-4">❌</div>
        <h1 class="text-2xl font-bold text-gray-800 mb-2">Activation Failed</h1>
        <p class="text-gray-500 text-sm mb-6"><?= e($error) ?></p>
        <a href="login.php" class="text-blue-600 hover:underline text-sm">← Back to login</a>
      <?php endif; ?>

    </div>
  </div>
</div>
<?php layoutEnd(); ?>

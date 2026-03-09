<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

$sent = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $user  = $authManager->getUserByEmail($email);

    // Always show success (prevents email enumeration)
    if ($user) {
        $authManager->requestPasswordReset($user, function ($user, $selector, $validator) {
            // In production, send an actual email.
            // Here we store the link in session so we can display it on screen (demo only).
            $link = 'http://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
                  . dirname($_SERVER['REQUEST_URI'] ?? '')
                  . "/reset-password.php?selector={$selector}&validator={$validator}";
            $_SESSION['_demo_reset_link'] = $link;
        });
    }
    $sent = true;
}

publicPage('Forgot Password');
?>
<div class="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
  <div class="w-full max-w-md">

    <div class="text-center mb-8">
      <div class="inline-flex items-center justify-center w-16 h-16 bg-white/10 backdrop-blur rounded-2xl mb-4 text-3xl">📧</div>
      <h1 class="text-2xl font-bold text-white">Reset Password</h1>
      <p class="text-blue-200 mt-1 text-sm">We'll send you a recovery link</p>
    </div>

    <div class="bg-white rounded-2xl shadow-2xl p-8 fade-in">

      <?php if ($sent): ?>
        <div class="text-center">
          <div class="text-5xl mb-4">✅</div>
          <h2 class="text-lg font-semibold text-gray-800 mb-2">Check your inbox</h2>
          <p class="text-sm text-gray-500 mb-4">
            If an account with that email exists, a reset link has been sent.
          </p>

          <?php if (!empty($_SESSION['_demo_reset_link'])): ?>
            <div class="mt-4 p-4 bg-yellow-50 border border-yellow-300 rounded-xl text-left">
              <p class="text-xs font-semibold text-yellow-700 mb-2">🔧 Demo mode — link shown here instead of email:</p>
              <a href="<?= e($_SESSION['_demo_reset_link']) ?>"
                 class="text-xs text-blue-600 break-all hover:underline">
                <?= e($_SESSION['_demo_reset_link']) ?>
              </a>
            </div>
            <?php unset($_SESSION['_demo_reset_link']); ?>
          <?php endif; ?>

          <a href="login.php" class="mt-4 inline-block text-sm text-blue-600 hover:underline">← Back to login</a>
        </div>
      <?php else: ?>
        <h2 class="text-xl font-semibold text-gray-800 mb-6">Enter your email address</h2>
        <form method="POST" class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Email Address</label>
            <input type="email" name="email" autofocus required
                   class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                   placeholder="john@example.com" />
          </div>
          <button type="submit"
                  class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition">
            Send Reset Link
          </button>
        </form>
        <p class="text-center text-sm text-gray-500 mt-5">
          <a href="login.php" class="text-blue-600 hover:underline">← Back to login</a>
        </p>
      <?php endif; ?>
    </div>
  </div>
</div>
<?php layoutEnd(); ?>

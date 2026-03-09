<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

authPage('JWT Demo', $authManager);
$user = $authManager->getLoggedInUser();

$generatedToken  = null;
$validationResult = null;
$revokeResult    = null;
$customResult    = null;
$error           = null;

// ── Handle actions ────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'generate':
            try {
                $expiry = (int) ($_POST['expiry'] ?? 3600);
                $generatedToken = $authManager->generateJwt($user, $expiry);
                $_SESSION['_demo_jwt'] = $generatedToken;
                flash('success', 'JWT generated successfully.');
            } catch (\RuntimeException $e) {
                flash('error', $e->getMessage());
            }
            break;

        case 'validate':
            $token = trim($_POST['token'] ?? '');
            if ($token) {
                $dto = $authManager->validateJwt($token);
                $validationResult = $dto;
                if (!$dto) {
                    flash('warning', 'Token is invalid, expired, or revoked.');
                }
            }
            break;

        case 'revoke':
            $token = trim($_POST['token'] ?? $_SESSION['_demo_jwt'] ?? '');
            if ($token) {
                $ok = $authManager->revokeJwt($token);
                if ($ok) {
                    flash('success', 'Token revoked. It will be rejected on next validation.');
                    unset($_SESSION['_demo_jwt']);
                } else {
                    flash('error', 'Could not revoke token (invalid or already expired).');
                }
            }
            break;
    }

    header('Location: jwt-demo.php');
    exit;
}

$storedToken = $_SESSION['_demo_jwt'] ?? null;

authPage('JWT Demo', $authManager);
$user = $authManager->getLoggedInUser();
?>
<?= renderFlash() ?>

<div class="max-w-3xl space-y-6">

  <!-- Explainer -->
  <div class="bg-blue-50 border border-blue-200 rounded-2xl p-5 text-sm text-blue-800">
    <strong class="font-semibold">What is JWT?</strong> JSON Web Tokens are signed, stateless tokens used for API
    authentication. The server signs the token with a secret; clients send it in the
    <code class="bg-blue-100 px-1 rounded">Authorization: Bearer &lt;token&gt;</code> header.
    No session or database lookup is needed per request — until the token is revoked.
  </div>

  <!-- Step 1 – Generate -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">1️⃣ Generate a JWT</h2>
    <form method="POST" class="flex items-end gap-3">
      <input type="hidden" name="action" value="generate" />
      <div>
        <label class="block text-xs font-medium text-gray-600 mb-1">Expiry (seconds)</label>
        <select name="expiry" class="px-3 py-2 border border-gray-300 rounded-xl text-sm bg-white focus:ring-2 focus:ring-blue-400 outline-none">
          <option value="60">60 s (1 minute — test revocation fast)</option>
          <option value="300">300 s (5 minutes)</option>
          <option value="3600" selected>3600 s (1 hour)</option>
          <option value="86400">86400 s (1 day)</option>
        </select>
      </div>
      <button type="submit"
              class="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl transition">
        🔑 Issue Token
      </button>
    </form>

    <?php if ($storedToken): ?>
      <div class="mt-4">
        <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Generated Token</label>
        <textarea id="generatedToken" rows="3" readonly onclick="this.select()"
                  class="w-full font-mono text-xs px-3 py-2 bg-gray-50 border border-gray-200 rounded-xl resize-none focus:ring-2 focus:ring-blue-400 outline-none text-gray-700">
<?= e($storedToken) ?></textarea>
        <div class="mt-2 flex gap-2">
          <button onclick="navigator.clipboard.writeText(document.getElementById('generatedToken').value); this.textContent='✓ Copied'"
                  class="text-xs px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition">
            📋 Copy
          </button>
          <button onclick="document.getElementById('validateInput').value = document.getElementById('generatedToken').value"
                  class="text-xs px-3 py-1 bg-blue-50 hover:bg-blue-100 text-blue-700 rounded-lg transition">
            ↓ Use in Validate
          </button>
          <button onclick="document.getElementById('revokeInput').value = document.getElementById('generatedToken').value"
                  class="text-xs px-3 py-1 bg-red-50 hover:bg-red-100 text-red-700 rounded-lg transition">
            ↓ Use in Revoke
          </button>
        </div>
      </div>
    <?php endif; ?>
  </div>

  <!-- Step 2 – Validate -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">2️⃣ Validate a JWT</h2>
    <form method="POST" class="space-y-3">
      <input type="hidden" name="action" value="validate" />
      <textarea id="validateInput" name="token" rows="3" required
                placeholder="Paste a JWT here..."
                class="w-full font-mono text-xs px-3 py-2 border border-gray-300 rounded-xl resize-none focus:ring-2 focus:ring-blue-400 outline-none"></textarea>
      <button type="submit"
              class="px-5 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-semibold rounded-xl transition">
        ✅ Validate
      </button>
    </form>

    <?php if (isset($validationResult)): ?>
      <?php if ($validationResult): ?>
        <div class="mt-4 p-4 bg-green-50 border border-green-300 rounded-xl">
          <p class="text-sm font-semibold text-green-700 mb-3">✓ Token is valid</p>
          <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
            <?php
            $rows = [
              'User ID'    => $validationResult->userId,
              'JTI'        => $validationResult->jti,
              'Issued At'  => date('Y-m-d H:i:s', $validationResult->issuedAt),
              'Expires At' => date('Y-m-d H:i:s', $validationResult->expiresAt),
              'Roles'      => implode(', ', $validationResult->roles) ?: '—',
              'Permissions'=> implode(', ', $validationResult->permissions) ?: '—',
            ];
            foreach ($rows as $k => $v):
            ?>
              <dt class="font-semibold text-gray-500"><?= e($k) ?></dt>
              <dd class="font-mono text-gray-800 truncate"><?= e((string)$v) ?></dd>
            <?php endforeach; ?>
          </dl>
        </div>
      <?php else: ?>
        <div class="mt-4 p-4 bg-red-50 border border-red-300 rounded-xl text-sm text-red-700">
          ✗ Token is <strong>invalid</strong>, <strong>expired</strong>, or <strong>revoked</strong>.
        </div>
      <?php endif; ?>
    <?php endif; ?>
  </div>

  <!-- Step 3 – Revoke -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">3️⃣ Revoke a JWT</h2>
    <p class="text-sm text-gray-500 mb-4">
      Revoking adds the token's JTI to the blacklist. It will be rejected on the next
      <code class="bg-gray-100 px-1 rounded">validateJwt()</code> call even if it hasn't expired.
    </p>
    <form method="POST" class="space-y-3">
      <input type="hidden" name="action" value="revoke" />
      <textarea id="revokeInput" name="token" rows="3" required
                placeholder="Paste the token to revoke..."
                class="w-full font-mono text-xs px-3 py-2 border border-gray-300 rounded-xl resize-none focus:ring-2 focus:ring-red-400 outline-none"></textarea>
      <button type="submit" onclick="return confirm('Revoke this token? It cannot be un-revoked.')"
              class="px-5 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-semibold rounded-xl transition">
        🚫 Revoke Token
      </button>
    </form>
  </div>

  <!-- API usage hint -->
  <div class="bg-gray-800 rounded-2xl p-6 text-sm">
    <h2 class="text-base font-semibold text-white mb-3">API Usage Example</h2>
    <pre class="text-green-300 text-xs overflow-x-auto leading-relaxed"><code><?php
echo htmlspecialchars(<<<'CODE'
// Issue a JWT for a logged-in user
$token = $authManager->generateJwt($user, expiry: 3600);

// In your API middleware — stateless, no session needed
$dto = $authManager->validateJwt($token); // Returns JwtDto or null
if ($dto === null) {
    http_response_code(401);
    exit('Unauthorized');
}

// Dto gives you userId, roles, permissions — no DB hit needed
$userId     = $dto->userId;
$hasAdmin   = in_array('Admin', $dto->roles);
$canEdit    = in_array('posts.edit', $dto->permissions);

// Revoke on user logout or security event
$authManager->revokeJwt($token);
CODE); ?></code></pre>
  </div>

</div>
<?php sidebarEnd(); layoutEnd(); ?>

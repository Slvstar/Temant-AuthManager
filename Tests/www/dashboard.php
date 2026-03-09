<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

authPage('Dashboard', $authManager);
$user    = $authManager->getLoggedInUser();
$roles   = $user->getRoles()->toArray();
$perms   = $user->listPermissions();
$attempts = array_slice(array_reverse($authManager->listAuthenticationAttempts($user)), 0, 5);
?>
<?= renderFlash() ?>

<!-- Stats row -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
  <?php
  $stats = [
    ['Account',       $user->getIsActivated() ? 'Active' : 'Inactive',  $user->getIsActivated() ? 'bg-green-50 border-green-200 text-green-700' : 'bg-red-50 border-red-200 text-red-700',   '✅'],
    ['Roles',         count($roles) . ' assigned',                        'bg-indigo-50 border-indigo-200 text-indigo-700', '🎭'],
    ['Permissions',   count($perms) . ' effective',                       'bg-purple-50 border-purple-200 text-purple-700', '🔑'],
    ['2FA',           $user->isTwoFactorEnabled() ? 'Enabled' : 'Off',   $user->isTwoFactorEnabled() ? 'bg-green-50 border-green-200 text-green-700' : 'bg-yellow-50 border-yellow-200 text-yellow-700', '🔒'],
  ];
  foreach ($stats as [$label, $value, $colors, $icon]):
  ?>
  <div class="bg-white rounded-2xl border p-5 <?= $colors ?> shadow-sm">
    <div class="flex items-center justify-between mb-2">
      <span class="text-xs font-semibold uppercase tracking-wider opacity-70"><?= $label ?></span>
      <span class="text-xl"><?= $icon ?></span>
    </div>
    <div class="text-2xl font-bold"><?= e($value) ?></div>
  </div>
  <?php endforeach; ?>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">

  <!-- User card -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">👤 Account Details</h2>
    <div class="flex items-center gap-4 mb-5">
      <div class="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white font-bold text-xl">
        <?= e($user->getInitials()) ?>
      </div>
      <div>
        <div class="text-lg font-bold text-gray-800"><?= e($user->getFullName()) ?></div>
        <div class="text-sm text-gray-500">@<?= e($user->getUserName()) ?></div>
      </div>
    </div>
    <div class="space-y-2.5 text-sm">
      <?php
      $rows = [
        ['Email',      e($user->getEmail())],
        ['Status',     badge($user->getIsActivated(), 'Active', 'Inactive') . ' ' . badge(!$user->getIsLocked(), 'Unlocked', 'Locked')],
        ['2FA',        badge($user->isTwoFactorEnabled(), 'Enabled', 'Disabled')],
        ['Member since', e($user->getCreatedAt()->format('M j, Y'))],
      ];
      foreach ($rows as [$label, $value]):
      ?>
      <div class="flex justify-between items-center py-1.5 border-b border-gray-50 last:border-0">
        <span class="text-gray-500"><?= $label ?></span>
        <span class="font-medium"><?= $value ?></span>
      </div>
      <?php endforeach; ?>
    </div>
    <div class="mt-4 flex gap-2">
      <a href="security.php" class="flex-1 text-center py-2 text-sm bg-blue-50 hover:bg-blue-100 text-blue-700 font-medium rounded-xl transition">
        🛡️ Security Settings
      </a>
      <?php if (!$user->isTwoFactorEnabled()): ?>
      <a href="security.php#2fa" class="flex-1 text-center py-2 text-sm bg-yellow-50 hover:bg-yellow-100 text-yellow-700 font-medium rounded-xl transition">
        🔒 Enable 2FA
      </a>
      <?php endif; ?>
    </div>
  </div>

  <!-- Roles & Permissions -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">🎭 Roles &amp; Permissions</h2>

    <?php if (empty($roles)): ?>
      <div class="text-sm text-gray-400 italic mb-4">No roles assigned.</div>
    <?php else: ?>
      <div class="mb-4">
        <div class="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Assigned Roles</div>
        <div class="flex flex-wrap gap-2">
          <?php foreach ($roles as $role): ?>
            <div class="group relative">
              <span class="px-3 py-1.5 rounded-xl text-sm font-medium bg-indigo-100 text-indigo-800 cursor-default flex items-center gap-1">
                🎭 <?= e($role->getName()) ?>
                <?php if ($role->getParent()): ?>
                  <span class="text-xs text-indigo-500">(inherits <?= e($role->getParent()->getName()) ?>)</span>
                <?php endif; ?>
              </span>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
    <?php endif; ?>

    <?php if (!empty($perms)): ?>
      <div>
        <div class="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
          Effective Permissions
          <span class="font-normal text-gray-300 ml-1">(via roles + direct grants)</span>
        </div>
        <div class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
          <?php foreach ($perms as $perm): ?>
            <?php
            $isDirect = $user->getDirectPermissions()->exists(
                fn($k, $p) => $p->getName() === $perm->getName()
            );
            $color = $isDirect ? 'bg-purple-100 text-purple-700' : 'bg-gray-100 text-gray-700';
            $icon  = $isDirect ? '⚡' : '🔑';
            ?>
            <span class="px-2.5 py-1 rounded-lg text-xs font-medium <?= $color ?>" title="<?= $isDirect ? 'Direct grant' : 'Via role' ?>">
              <?= $icon ?> <?= e($perm->getName()) ?>
            </span>
          <?php endforeach; ?>
        </div>
        <p class="text-xs text-gray-400 mt-2">⚡ = direct grant &nbsp; 🔑 = via role</p>
      </div>
    <?php else: ?>
      <div class="text-sm text-gray-400 italic">No permissions assigned.</div>
    <?php endif; ?>
  </div>
</div>

<!-- Recent login attempts -->
<div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
  <h2 class="text-base font-semibold text-gray-800 mb-4 flex items-center gap-2">📋 Recent Login Attempts</h2>
  <?php if (empty($attempts)): ?>
    <p class="text-sm text-gray-400 italic">No login attempts recorded.</p>
  <?php else: ?>
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="text-xs uppercase tracking-wider text-gray-400 border-b border-gray-100">
            <th class="text-left pb-3 pr-4">Status</th>
            <th class="text-left pb-3 pr-4">Reason</th>
            <th class="text-left pb-3 pr-4">IP Address</th>
            <th class="text-left pb-3">Date</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-50">
          <?php foreach ($attempts as $attempt): ?>
          <tr>
            <td class="py-2 pr-4"><?= badge($attempt->getSuccess(), 'Success', 'Failed') ?></td>
            <td class="py-2 pr-4 text-gray-500"><?= e($attempt->getReason() ?? '—') ?></td>
            <td class="py-2 pr-4 font-mono text-gray-500 text-xs"><?= e($attempt->getIpAddress() ?? '—') ?></td>
            <td class="py-2 text-gray-400 text-xs"><?= e($attempt->getCreatedAt()->format('M j, Y H:i:s')) ?></td>
          </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  <?php endif; ?>
</div>

<?php sidebarEnd(); layoutEnd(); ?>

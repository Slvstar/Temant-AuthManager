<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

authPage('Admin Panel', $authManager);
$user = $authManager->getLoggedInUser();

// Only allow users with Admin role or admin.access permission
if (!$user->hasRole('Admin') && !$user->hasPermission('admin.access')) {
    flash('error', 'Access denied. You need the Admin role or admin.access permission.');
    header('Location: dashboard.php');
    exit;
}

// ── Handle actions ────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    try {
        switch ($action) {
            // ── Role actions ───────────────────────────────────────────────
            case 'create_role':
                $name   = trim($_POST['role_name'] ?? '');
                $desc   = trim($_POST['role_desc'] ?? '') ?: null;
                $pid    = (int) ($_POST['parent_id'] ?? 0);
                $parent = null;
                if ($pid) {
                    foreach ($authManager->listAllRoles() as $r) {
                        if ($r->getId() === $pid) { $parent = $r; break; }
                    }
                }
                if ($name) {
                    $authManager->createRole($name, $desc, $parent);
                    flash('success', "Role '{$name}' created.");
                }
                break;

            case 'delete_role':
                foreach ($authManager->listAllRoles() as $r) {
                    if ($r->getId() === (int) $_POST['role_id']) {
                        $authManager->deleteRole($r);
                        flash('success', "Role deleted.");
                        break;
                    }
                }
                break;

            // ── Permission actions ─────────────────────────────────────────
            case 'create_permission':
                $name = trim($_POST['perm_name'] ?? '');
                $desc = trim($_POST['perm_desc'] ?? '') ?: null;
                if ($name) {
                    $authManager->createPermission($name, $desc);
                    flash('success', "Permission '{$name}' created.");
                }
                break;

            case 'delete_permission':
                foreach ($authManager->listAllPermissions() as $p) {
                    if ($p->getId() === (int) $_POST['perm_id']) {
                        $authManager->deletePermission($p);
                        flash('success', 'Permission deleted.');
                        break;
                    }
                }
                break;

            // ── Role ↔ Permission ──────────────────────────────────────────
            case 'add_perm_to_role':
                $role = $perm = null;
                foreach ($authManager->listAllRoles()       as $r) { if ($r->getId() === (int)$_POST['role_id']) $role = $r; }
                foreach ($authManager->listAllPermissions() as $p) { if ($p->getId() === (int)$_POST['perm_id']) $perm = $p; }
                if ($role && $perm) { $authManager->addPermissionToRole($role, $perm); flash('success', "Permission added to role."); }
                break;

            case 'remove_perm_from_role':
                $role = $perm = null;
                foreach ($authManager->listAllRoles()       as $r) { if ($r->getId() === (int)$_POST['role_id']) $role = $r; }
                foreach ($authManager->listAllPermissions() as $p) { if ($p->getId() === (int)$_POST['perm_id']) $perm = $p; }
                if ($role && $perm) { $authManager->removePermissionFromRole($role, $perm); flash('success', "Permission removed from role."); }
                break;

            // ── User ↔ Role ────────────────────────────────────────────────
            case 'assign_role':
                $target = $authManager->getUser((int) $_POST['user_id']);
                $role   = null;
                foreach ($authManager->listAllRoles() as $r) { if ($r->getId() === (int)$_POST['role_id']) $role = $r; }
                if ($target && $role) { $authManager->assignRole($target, $role); flash('success', "Role assigned to user."); }
                break;

            case 'remove_user_role':
                $target = $authManager->getUser((int) $_POST['user_id']);
                $role   = null;
                foreach ($authManager->listAllRoles() as $r) { if ($r->getId() === (int)$_POST['role_id']) $role = $r; }
                if ($target && $role) { $authManager->removeRoleFromUser($target, $role); flash('success', "Role removed from user."); }
                break;

            // ── User ↔ Direct Permission ───────────────────────────────────
            case 'assign_direct_perm':
                $target = $authManager->getUser((int) $_POST['user_id']);
                $perm   = null;
                foreach ($authManager->listAllPermissions() as $p) { if ($p->getId() === (int)$_POST['perm_id']) $perm = $p; }
                if ($target && $perm) { $authManager->assignDirectPermission($target, $perm); flash('success', "Direct permission granted."); }
                break;

            case 'remove_direct_perm':
                $target = $authManager->getUser((int) $_POST['user_id']);
                $perm   = null;
                foreach ($authManager->listAllPermissions() as $p) { if ($p->getId() === (int)$_POST['perm_id']) $perm = $p; }
                if ($target && $perm) { $authManager->removeDirectPermission($target, $perm); flash('success', "Direct permission removed."); }
                break;

            // ── User account ───────────────────────────────────────────────
            case 'toggle_lock':
                $target = $authManager->getUser((int) $_POST['user_id']);
                if ($target) {
                    $target->getIsLocked() ? $authManager->unlockAccount($target) : $authManager->lockAccount($target);
                    flash('success', "Account " . ($target->getIsLocked() ? 'locked' : 'unlocked') . '.');
                }
                break;

            case 'toggle_activate':
                $target = $authManager->getUser((int) $_POST['user_id']);
                if ($target) {
                    $target->getIsActivated() ? $authManager->deactivateAccount($target) : $authManager->activateAccount($target);
                    flash('success', "Account status changed.");
                }
                break;
        }
    } catch (\Exception $e) {
        flash('error', $e->getMessage());
    }

    header('Location: admin.php?tab=' . ($_GET['tab'] ?? 'users'));
    exit;
}

$allUsers  = $authManager->listAllRegistredUsers();
$allRoles  = $authManager->listAllRoles();
$allPerms  = $authManager->listAllPermissions();
$activeTab = $_GET['tab'] ?? 'users';

authPage('Admin Panel', $authManager);
$user = $authManager->getLoggedInUser();
?>
<?= renderFlash() ?>

<!-- Tabs -->
<div class="flex gap-1 mb-6 bg-white border border-gray-200 rounded-2xl p-1 shadow-sm w-fit">
  <?php foreach (['users' => '👥 Users', 'roles' => '🎭 Roles', 'permissions' => '🔑 Permissions'] as $tab => $label): ?>
    <a href="?tab=<?= $tab ?>"
       class="px-5 py-2 rounded-xl text-sm font-medium transition
              <?= $activeTab === $tab ? 'bg-blue-600 text-white shadow-sm' : 'text-gray-600 hover:bg-gray-100' ?>">
      <?= $label ?>
    </a>
  <?php endforeach; ?>
</div>

<?php if ($activeTab === 'users'): ?>
<!-- ── Users tab ─────────────────────────────────────────────────────────── -->
<div class="space-y-4">
  <?php foreach ($allUsers as $u): ?>
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-5">
    <div class="flex items-start justify-between gap-4">
      <div class="flex items-center gap-4">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-400 to-indigo-500 flex items-center justify-center text-white font-bold text-sm">
          <?= e($u->getInitials()) ?>
        </div>
        <div>
          <div class="font-semibold text-gray-800"><?= e($u->getFullName()) ?></div>
          <div class="text-xs text-gray-400">@<?= e($u->getUserName()) ?> · <?= e($u->getEmail()) ?></div>
        </div>
      </div>
      <div class="flex items-center gap-2 flex-wrap justify-end">
        <?= badge($u->getIsActivated(), 'Active', 'Inactive') ?>
        <?= badge(!$u->getIsLocked(), 'Unlocked', 'Locked') ?>
        <?= badge($u->isTwoFactorEnabled(), '2FA', 'No 2FA') ?>
        <!-- Lock/Unlock -->
        <form method="POST" class="inline">
          <input type="hidden" name="action"  value="toggle_lock" />
          <input type="hidden" name="user_id" value="<?= $u->getId() ?>" />
          <button type="submit"
                  class="px-3 py-1 text-xs rounded-lg font-medium transition
                         <?= $u->getIsLocked() ? 'bg-green-100 hover:bg-green-200 text-green-700' : 'bg-red-100 hover:bg-red-200 text-red-700' ?>">
            <?= $u->getIsLocked() ? '🔓 Unlock' : '🔒 Lock' ?>
          </button>
        </form>
        <!-- Activate/Deactivate -->
        <form method="POST" class="inline">
          <input type="hidden" name="action"  value="toggle_activate" />
          <input type="hidden" name="user_id" value="<?= $u->getId() ?>" />
          <button type="submit"
                  class="px-3 py-1 text-xs rounded-lg font-medium transition
                         <?= $u->getIsActivated() ? 'bg-yellow-100 hover:bg-yellow-200 text-yellow-700' : 'bg-green-100 hover:bg-green-200 text-green-700' ?>">
            <?= $u->getIsActivated() ? '⏸ Deactivate' : '▶ Activate' ?>
          </button>
        </form>
      </div>
    </div>

    <!-- Roles -->
    <div class="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
      <div>
        <div class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Roles</div>
        <div class="flex flex-wrap gap-1 mb-2 min-h-[24px]">
          <?php foreach ($u->getRoles() as $r): ?>
            <div class="flex items-center gap-1 px-2 py-0.5 bg-indigo-100 text-indigo-700 rounded-full text-xs font-medium">
              <?= e($r->getName()) ?>
              <form method="POST" class="inline">
                <input type="hidden" name="action"  value="remove_user_role" />
                <input type="hidden" name="user_id" value="<?= $u->getId() ?>" />
                <input type="hidden" name="role_id" value="<?= $r->getId() ?>" />
                <button type="submit" class="text-indigo-400 hover:text-red-500 leading-none ml-0.5" title="Remove">×</button>
              </form>
            </div>
          <?php endforeach; ?>
          <?php if ($u->getRoles()->isEmpty()): ?>
            <span class="text-xs text-gray-400 italic">No roles</span>
          <?php endif; ?>
        </div>
        <?php if (!empty($allRoles)): ?>
        <form method="POST" class="flex gap-2">
          <input type="hidden" name="action"  value="assign_role" />
          <input type="hidden" name="user_id" value="<?= $u->getId() ?>" />
          <select name="role_id" class="text-xs border border-gray-200 rounded-lg px-2 py-1 bg-white focus:ring-1 focus:ring-blue-400 outline-none">
            <?php foreach ($allRoles as $r): ?>
              <option value="<?= $r->getId() ?>"><?= e($r->getName()) ?></option>
            <?php endforeach; ?>
          </select>
          <button type="submit" class="px-2.5 py-1 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs rounded-lg font-medium transition">+ Assign</button>
        </form>
        <?php endif; ?>
      </div>

      <div>
        <div class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Direct Permissions</div>
        <div class="flex flex-wrap gap-1 mb-2 min-h-[24px]">
          <?php foreach ($u->getDirectPermissions() as $p): ?>
            <div class="flex items-center gap-1 px-2 py-0.5 bg-purple-100 text-purple-700 rounded-full text-xs font-medium">
              <?= e($p->getName()) ?>
              <form method="POST" class="inline">
                <input type="hidden" name="action"  value="remove_direct_perm" />
                <input type="hidden" name="user_id" value="<?= $u->getId() ?>" />
                <input type="hidden" name="perm_id" value="<?= $p->getId() ?>" />
                <button type="submit" class="text-purple-400 hover:text-red-500 leading-none ml-0.5" title="Remove">×</button>
              </form>
            </div>
          <?php endforeach; ?>
          <?php if ($u->getDirectPermissions()->isEmpty()): ?>
            <span class="text-xs text-gray-400 italic">None</span>
          <?php endif; ?>
        </div>
        <?php if (!empty($allPerms)): ?>
        <form method="POST" class="flex gap-2">
          <input type="hidden" name="action"  value="assign_direct_perm" />
          <input type="hidden" name="user_id" value="<?= $u->getId() ?>" />
          <select name="perm_id" class="text-xs border border-gray-200 rounded-lg px-2 py-1 bg-white focus:ring-1 focus:ring-purple-400 outline-none">
            <?php foreach ($allPerms as $p): ?>
              <option value="<?= $p->getId() ?>"><?= e($p->getName()) ?></option>
            <?php endforeach; ?>
          </select>
          <button type="submit" class="px-2.5 py-1 bg-purple-50 hover:bg-purple-100 text-purple-700 text-xs rounded-lg font-medium transition">⚡ Grant</button>
        </form>
        <?php endif; ?>
      </div>
    </div>
  </div>
  <?php endforeach; ?>
</div>

<?php elseif ($activeTab === 'roles'): ?>
<!-- ── Roles tab ──────────────────────────────────────────────────────────── -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

  <!-- Create role form -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4">Create Role</h2>
    <form method="POST" class="space-y-3">
      <input type="hidden" name="action" value="create_role" />
      <div>
        <label class="block text-xs font-medium text-gray-600 mb-1">Name <span class="text-red-400">*</span></label>
        <input type="text" name="role_name" required placeholder="e.g. Editor"
               class="w-full px-3 py-2 border border-gray-300 rounded-xl text-sm focus:ring-2 focus:ring-blue-400 outline-none" />
      </div>
      <div>
        <label class="block text-xs font-medium text-gray-600 mb-1">Description</label>
        <input type="text" name="role_desc" placeholder="Optional description"
               class="w-full px-3 py-2 border border-gray-300 rounded-xl text-sm focus:ring-2 focus:ring-blue-400 outline-none" />
      </div>
      <div>
        <label class="block text-xs font-medium text-gray-600 mb-1">Parent Role (inherits permissions)</label>
        <select name="parent_id" class="w-full px-3 py-2 border border-gray-300 rounded-xl text-sm bg-white focus:ring-2 focus:ring-blue-400 outline-none">
          <option value="0">— None (top-level) —</option>
          <?php foreach ($allRoles as $r): ?>
            <option value="<?= $r->getId() ?>"><?= e($r->getName()) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <button type="submit" class="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-xl transition">
        Create Role
      </button>
    </form>
  </div>

  <!-- Existing roles -->
  <div class="space-y-3">
    <?php if (empty($allRoles)): ?>
      <div class="bg-white rounded-2xl border border-dashed border-gray-300 p-6 text-center text-sm text-gray-400">
        No roles yet. Create one to get started.
      </div>
    <?php endif; ?>
    <?php foreach ($allRoles as $role): ?>
    <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-5">
      <div class="flex items-start justify-between gap-3">
        <div>
          <div class="font-semibold text-gray-800"><?= e($role->getName()) ?></div>
          <?php if ($role->getDescription()): ?>
            <div class="text-xs text-gray-400 mt-0.5"><?= e($role->getDescription()) ?></div>
          <?php endif; ?>
          <?php if ($role->getParent()): ?>
            <div class="text-xs text-indigo-500 mt-0.5">↳ inherits from <?= e($role->getParent()->getName()) ?></div>
          <?php endif; ?>
        </div>
        <form method="POST" onsubmit="return confirm('Delete this role?')">
          <input type="hidden" name="action"  value="delete_role" />
          <input type="hidden" name="role_id" value="<?= $role->getId() ?>" />
          <button type="submit" class="px-3 py-1 bg-red-50 hover:bg-red-100 text-red-600 text-xs rounded-lg font-medium transition">Delete</button>
        </form>
      </div>

      <!-- Permissions on this role -->
      <div class="mt-3">
        <div class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">Own Permissions</div>
        <div class="flex flex-wrap gap-1 mb-2">
          <?php foreach ($role->getPermissions() as $p): ?>
            <div class="flex items-center gap-1 px-2 py-0.5 bg-green-100 text-green-700 rounded-full text-xs font-medium">
              <?= e($p->getName()) ?>
              <form method="POST" class="inline">
                <input type="hidden" name="action"  value="remove_perm_from_role" />
                <input type="hidden" name="role_id" value="<?= $role->getId() ?>" />
                <input type="hidden" name="perm_id" value="<?= $p->getId() ?>" />
                <button class="text-green-400 hover:text-red-500 leading-none ml-0.5">×</button>
              </form>
            </div>
          <?php endforeach; ?>
          <?php if ($role->getPermissions()->isEmpty()): ?>
            <span class="text-xs text-gray-400 italic">No permissions</span>
          <?php endif; ?>
        </div>
        <?php if (!empty($allPerms)): ?>
        <form method="POST" class="flex gap-2">
          <input type="hidden" name="action"  value="add_perm_to_role" />
          <input type="hidden" name="role_id" value="<?= $role->getId() ?>" />
          <select name="perm_id" class="text-xs border border-gray-200 rounded-lg px-2 py-1 bg-white focus:ring-1 focus:ring-green-400 outline-none">
            <?php foreach ($allPerms as $p): ?>
              <option value="<?= $p->getId() ?>"><?= e($p->getName()) ?></option>
            <?php endforeach; ?>
          </select>
          <button type="submit" class="px-2.5 py-1 bg-green-50 hover:bg-green-100 text-green-700 text-xs rounded-lg font-medium transition">+ Add</button>
        </form>
        <?php endif; ?>
      </div>
      <div class="text-xs text-gray-400 mt-2">
        <?= count($role->getUsers()->toArray()) ?> user(s) · <?= count($role->getPermissions()->toArray()) ?> own permission(s)
      </div>
    </div>
    <?php endforeach; ?>
  </div>
</div>

<?php else: ?>
<!-- ── Permissions tab ────────────────────────────────────────────────────── -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

  <!-- Create permission form -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
    <h2 class="text-base font-semibold text-gray-800 mb-4">Create Permission</h2>
    <form method="POST" class="space-y-3">
      <input type="hidden" name="action" value="create_permission" />
      <div>
        <label class="block text-xs font-medium text-gray-600 mb-1">Name <span class="text-red-400">*</span></label>
        <input type="text" name="perm_name" required placeholder="e.g. posts.edit"
               class="w-full px-3 py-2 border border-gray-300 rounded-xl text-sm focus:ring-2 focus:ring-purple-400 outline-none" />
        <p class="text-xs text-gray-400 mt-1">Use dot-notation: resource.action (e.g. posts.delete)</p>
      </div>
      <div>
        <label class="block text-xs font-medium text-gray-600 mb-1">Description</label>
        <input type="text" name="perm_desc" placeholder="Optional description"
               class="w-full px-3 py-2 border border-gray-300 rounded-xl text-sm focus:ring-2 focus:ring-purple-400 outline-none" />
      </div>
      <button type="submit" class="px-5 py-2 bg-purple-600 hover:bg-purple-700 text-white text-sm font-semibold rounded-xl transition">
        Create Permission
      </button>
    </form>
  </div>

  <!-- Existing permissions -->
  <div class="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
    <div class="p-5 border-b border-gray-100">
      <h2 class="text-base font-semibold text-gray-800">All Permissions (<?= count($allPerms) ?>)</h2>
    </div>
    <?php if (empty($allPerms)): ?>
      <div class="p-6 text-center text-sm text-gray-400">No permissions yet.</div>
    <?php else: ?>
    <div class="divide-y divide-gray-50">
      <?php foreach ($allPerms as $p): ?>
      <div class="px-5 py-3 flex items-center justify-between">
        <div>
          <span class="font-mono text-sm font-medium text-gray-800"><?= e($p->getName()) ?></span>
          <?php if ($p->getDescription()): ?>
            <span class="text-xs text-gray-400 ml-2">— <?= e($p->getDescription()) ?></span>
          <?php endif; ?>
          <div class="text-xs text-gray-400 mt-0.5">
            Used in <?= count($p->getRoles()->toArray()) ?> role(s)
          </div>
        </div>
        <form method="POST" onsubmit="return confirm('Delete this permission?')">
          <input type="hidden" name="action"  value="delete_permission" />
          <input type="hidden" name="perm_id" value="<?= $p->getId() ?>" />
          <button type="submit" class="px-3 py-1 bg-red-50 hover:bg-red-100 text-red-600 text-xs rounded-lg font-medium transition">Delete</button>
        </form>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </div>
</div>
<?php endif; ?>

<?php sidebarEnd(); layoutEnd(); ?>

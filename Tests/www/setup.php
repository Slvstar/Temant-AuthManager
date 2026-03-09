<?php declare(strict_types=1);

/**
 * Demo seed page — run this once to create roles, permissions, and a test admin user.
 * DELETE or protect this file before going to production.
 */

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

$log = [];
$ok  = true;

function seedLog(string $msg, bool $success = true): void
{
    global $log;
    $log[] = [$msg, $success];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // ── Permissions ───────────────────────────────────────────────────────
        $permissions = [
            ['admin.access',  'Access the admin panel'],
            ['posts.view',    'View published posts'],
            ['posts.create',  'Create new posts'],
            ['posts.edit',    'Edit existing posts'],
            ['posts.delete',  'Delete posts'],
            ['users.manage',  'Manage user accounts'],
            ['comments.moderate', 'Moderate user comments'],
        ];

        $permMap = [];
        foreach ($authManager->listAllPermissions() as $p) {
            $permMap[$p->getName()] = $p;
        }

        foreach ($permissions as [$name, $desc]) {
            if (!isset($permMap[$name])) {
                $permMap[$name] = $authManager->createPermission($name, $desc);
                seedLog("Created permission: {$name}");
            } else {
                seedLog("Permission already exists: {$name}");
            }
        }

        // ── Roles (with hierarchy) ────────────────────────────────────────────
        $roleMap = [];
        foreach ($authManager->listAllRoles() as $r) {
            $roleMap[$r->getName()] = $r;
        }

        // Viewer (base)
        if (!isset($roleMap['Viewer'])) {
            $roleMap['Viewer'] = $authManager->createRole('Viewer', 'Can view content only');
            seedLog("Created role: Viewer");
        }
        $authManager->addPermissionToRole($roleMap['Viewer'], $permMap['posts.view']);

        // Editor inherits from Viewer
        if (!isset($roleMap['Editor'])) {
            $roleMap['Editor'] = $authManager->createRole('Editor', 'Can create and edit posts', $roleMap['Viewer']);
            seedLog("Created role: Editor (inherits Viewer)");
        }
        foreach (['posts.create', 'posts.edit', 'comments.moderate'] as $p) {
            $authManager->addPermissionToRole($roleMap['Editor'], $permMap[$p]);
        }

        // Admin inherits from Editor
        if (!isset($roleMap['Admin'])) {
            $roleMap['Admin'] = $authManager->createRole('Admin', 'Full system access', $roleMap['Editor']);
            seedLog("Created role: Admin (inherits Editor → Viewer)");
        }
        foreach (['admin.access', 'posts.delete', 'users.manage'] as $p) {
            $authManager->addPermissionToRole($roleMap['Admin'], $permMap[$p]);
        }

        // ── Demo users ────────────────────────────────────────────────────────
        $users = [
            ['Admin', 'User',   'admin@demo.com',   'Admin123!', 'Admin'],
            ['Editor','Smith',  'editor@demo.com',  'Admin123!', 'Editor'],
            ['John',  'Viewer', 'viewer@demo.com',  'Admin123!', 'Viewer'],
        ];

        foreach ($users as [$first, $last, $email, $pass, $roleName]) {
            $existing = $authManager->getUserByEmail($email);
            if (!$existing) {
                $u = $authManager->registerUser($first, $last, $email, $pass, $roleMap[$roleName]);
                if ($u) {
                    $authManager->activateAccount($u);
                    seedLog("Created + activated user: {$email} with role {$roleName}");
                }
            } else {
                // Ensure activated
                $authManager->activateAccount($existing);
                seedLog("User already exists: {$email}");
            }
        }

        // Grant a direct permission to the admin user as a demo
        $adminUser = $authManager->getUserByEmail('admin@demo.com');
        if ($adminUser) {
            $authManager->assignDirectPermission($adminUser, $permMap['users.manage']);
            seedLog("Granted direct permission 'users.manage' to admin@demo.com");
        }

    } catch (\Exception $e) {
        $ok = false;
        seedLog('ERROR: ' . $e->getMessage(), false);
    }
}

publicPage('Demo Setup');
?>
<div class="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
  <div class="w-full max-w-lg">

    <div class="text-center mb-8">
      <div class="inline-flex items-center justify-center w-16 h-16 bg-white/10 backdrop-blur rounded-2xl mb-4 text-3xl">⚙️</div>
      <h1 class="text-2xl font-bold text-white">Demo Setup</h1>
      <p class="text-blue-200 mt-1 text-sm">Seeds roles, permissions, and demo users</p>
    </div>

    <div class="bg-white rounded-2xl shadow-2xl p-8 fade-in">

      <?php if (!empty($log)): ?>
        <div class="mb-6 space-y-1.5 max-h-64 overflow-y-auto">
          <?php foreach ($log as [$msg, $success]): ?>
            <div class="flex items-start gap-2 text-sm <?= $success ? 'text-green-700' : 'text-red-600' ?>">
              <span class="font-bold shrink-0"><?= $success ? '✓' : '✗' ?></span>
              <span><?= e($msg) ?></span>
            </div>
          <?php endforeach; ?>
        </div>

        <?php if ($ok): ?>
          <div class="mb-5 p-4 bg-green-50 border border-green-300 rounded-xl text-sm text-green-700">
            <strong>Setup complete!</strong> You can now log in with the demo accounts below.
          </div>
        <?php endif; ?>
      <?php endif; ?>

      <?php if (empty($log)): ?>
        <p class="text-sm text-gray-600 mb-6">
          This will create the following in your database:
        </p>
        <div class="space-y-3 mb-6">
          <div class="p-3 bg-indigo-50 border border-indigo-200 rounded-xl text-sm">
            <strong class="text-indigo-700">Roles</strong>
            <div class="text-gray-600 mt-1 text-xs">
              Viewer → Editor (inherits Viewer) → Admin (inherits Editor)
            </div>
          </div>
          <div class="p-3 bg-purple-50 border border-purple-200 rounded-xl text-sm">
            <strong class="text-purple-700">Permissions</strong>
            <div class="text-gray-600 mt-1 text-xs">
              admin.access, posts.view/create/edit/delete, users.manage, comments.moderate
            </div>
          </div>
          <div class="p-3 bg-blue-50 border border-blue-200 rounded-xl text-sm">
            <strong class="text-blue-700">Demo Users</strong>
            <div class="text-xs mt-1 space-y-1 text-gray-600">
              <div>admin@demo.com / Admin123! <em>(Admin role)</em></div>
              <div>editor@demo.com / Admin123! <em>(Editor role)</em></div>
              <div>viewer@demo.com / Admin123! <em>(Viewer role)</em></div>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <div class="flex gap-3">
        <form method="POST" class="flex-1">
          <button type="submit"
                  class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition">
            <?= empty($log) ? '🚀 Run Setup' : '🔄 Run Again' ?>
          </button>
        </form>
        <a href="login.php"
           class="flex-1 py-2.5 text-center bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold rounded-xl transition text-sm">
          → Login
        </a>
      </div>

      <div class="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-xl text-xs text-yellow-700">
        ⚠️ <strong>Remove this file</strong> before deploying to production.
      </div>
    </div>
  </div>
</div>
<?php layoutEnd(); ?>

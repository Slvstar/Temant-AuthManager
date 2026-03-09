<?php declare(strict_types=1);

require_once __DIR__ . '/../Bootstrap.php';
require_once __DIR__ . '/_helpers.php';

use Temant\AuthManager\Exceptions\EmailNotValidException;
use Temant\AuthManager\Exceptions\WeakPasswordException;

if ($authManager->isAuthenticated()) {
    header('Location: dashboard.php');
    exit;
}

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $firstName = trim($_POST['first_name'] ?? '');
    $lastName  = trim($_POST['last_name']  ?? '');
    $email     = trim($_POST['email']      ?? '');
    $password  = $_POST['password']        ?? '';
    $confirm   = $_POST['confirm']         ?? '';
    $roleId    = (int) ($_POST['role_id']  ?? 0);

    saveOld(['first_name' => $firstName, 'last_name' => $lastName, 'email' => $email]);

    if ($password !== $confirm) {
        $errors[] = 'Passwords do not match.';
    }

    if (empty($errors)) {
        try {
            $role = $roleId ? $authManager->listAllRoles()[array_search(
                $roleId,
                array_map(fn($r) => $r->getId(), $authManager->listAllRoles())
            )] : null;

            // Find role by ID more cleanly
            $selectedRole = null;
            foreach ($authManager->listAllRoles() as $r) {
                if ($r->getId() === $roleId) {
                    $selectedRole = $r;
                    break;
                }
            }

            $user = $authManager->registerUser($firstName, $lastName, $email, $password, $selectedRole);

            if ($user) {
                flash('success', 'Account created! ' . (
                    // Check if mail_verify is enabled via settings
                    'You can now sign in.'
                ));
                header('Location: login.php');
                exit;
            }
        } catch (WeakPasswordException $e) {
            $errors[] = 'Weak password: ' . $e->getMessage();
        } catch (EmailNotValidException $e) {
            $errors[] = 'Invalid email: ' . $e->getMessage();
        } catch (\Exception $e) {
            $errors[] = 'Registration failed: ' . $e->getMessage();
        }
    }
}

$roles = $authManager->listAllRoles();

publicPage('Register');
?>
<div class="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
  <div class="w-full max-w-lg">

    <div class="text-center mb-8">
      <div class="inline-flex items-center justify-center w-16 h-16 bg-white/10 backdrop-blur rounded-2xl mb-4 text-3xl">🔐</div>
      <h1 class="text-3xl font-bold text-white">Create Account</h1>
      <p class="text-blue-200 mt-1 text-sm">Join the AuthManager demo</p>
    </div>

    <div class="bg-white rounded-2xl shadow-2xl p-8 fade-in">
      <h2 class="text-xl font-semibold text-gray-800 mb-6">Your details</h2>

      <?php foreach ($errors as $err): ?>
        <div class="mb-3 p-3 rounded-xl bg-red-50 border border-red-300 text-red-700 text-sm flex items-start gap-2">
          <span class="font-bold">✗</span><span><?= e($err) ?></span>
        </div>
      <?php endforeach; ?>

      <form method="POST" class="space-y-4">
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">First Name</label>
            <input type="text" name="first_name" value="<?= old('first_name') ?>"
                   class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                   placeholder="John" required />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Last Name</label>
            <input type="text" name="last_name" value="<?= old('last_name') ?>"
                   class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                   placeholder="Doe" required />
          </div>
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Email Address</label>
          <input type="email" name="email" value="<?= old('email') ?>"
                 class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                 placeholder="john@example.com" required />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Password</label>
          <input type="password" name="password"
                 class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                 placeholder="Min. 8 chars, upper, lower, number" required />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
          <input type="password" name="confirm"
                 class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm"
                 placeholder="••••••••" required />
        </div>

        <?php if (!empty($roles)): ?>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Role <span class="text-gray-400 font-normal">(optional)</span></label>
          <select name="role_id"
                  class="w-full px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 outline-none text-sm bg-white">
            <option value="0">— No role —</option>
            <?php foreach ($roles as $r): ?>
              <option value="<?= e((string)$r->getId()) ?>">
                <?= e($r->getName()) ?><?= $r->getDescription() ? ' — ' . e($r->getDescription()) : '' ?>
              </option>
            <?php endforeach; ?>
          </select>
        </div>
        <?php endif; ?>

        <button type="submit"
                class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition shadow-sm mt-2">
          Create Account
        </button>
      </form>

      <p class="text-center text-sm text-gray-500 mt-6">
        Already have an account?
        <a href="login.php" class="text-blue-600 font-medium hover:underline">Sign in</a>
      </p>
    </div>
  </div>
</div>
<?php layoutEnd(); ?>

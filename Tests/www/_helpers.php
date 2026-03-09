<?php declare(strict_types=1);

// ── Flash messages ────────────────────────────────────────────────────────────

function flash(string $type, string $message): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['_flash'][] = ['type' => $type, 'msg' => $message];
    }
}

function renderFlash(): string
{
    if (empty($_SESSION['_flash'])) {
        return '';
    }
    $out = '';
    foreach ((array) $_SESSION['_flash'] as $f) {
        [$bg, $border, $text, $icon] = match ($f['type']) {
            'success' => ['bg-green-50', 'border-green-400', 'text-green-800', '✓'],
            'error'   => ['bg-red-50', 'border-red-400', 'text-red-800', '✗'],
            'warning' => ['bg-yellow-50', 'border-yellow-400', 'text-yellow-800', '⚠'],
            default   => ['bg-blue-50', 'border-blue-400', 'text-blue-800', 'ℹ'],
        };
        $out .= "<div class=\"flex items-start gap-3 mb-3 p-4 rounded-xl border {$bg} {$border} {$text}\">"
              . "<span class=\"font-bold text-lg leading-tight\">{$icon}</span>"
              . "<span class=\"text-sm\">" . e($f['msg']) . "</span></div>\n";
    }
    $_SESSION['_flash'] = [];
    return $out;
}

// ── HTML helpers ─────────────────────────────────────────────────────────────

function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function old(string $key, string $default = ''): string
{
    return e($_SESSION['_old'][$key] ?? $default);
}

function saveOld(array $data): void
{
    $_SESSION['_old'] = $data;
}

function badge(bool $value, string $yes = 'Yes', string $no = 'No'): string
{
    return $value
        ? "<span class=\"px-2 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700\">{$yes}</span>"
        : "<span class=\"px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700\">{$no}</span>";
}

function pill(string $label, string $color = 'blue'): string
{
    return "<span class=\"px-2 py-0.5 rounded-full text-xs font-semibold bg-{$color}-100 text-{$color}-700\">{$label}</span>";
}

// ── Layout ────────────────────────────────────────────────────────────────────

function layoutStart(string $title, bool $sidebar = true): void
{
    echo <<<HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>{$title} — AuthManager Demo</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            [x-cloak] { display: none !important; }
            .fade-in { animation: fadeIn .25s ease-in; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
        </style>
    </head>
    <body class="bg-gray-50 text-gray-800 antialiased">
    HTML;
}

function layoutEnd(): void
{
    echo "</body></html>\n";
}

function authPage(string $title, \Temant\AuthManager\AuthManager $authManager): void
{
    if (!$authManager->isAuthenticated()) {
        header('Location: login.php');
        exit;
    }
    layoutStart($title);
    renderSidebar($authManager, $title);
}

function renderSidebar(\Temant\AuthManager\AuthManager $authManager, string $activeTitle): void
{
    $user    = $authManager->getLoggedInUser();
    $current = basename($_SERVER['PHP_SELF']);
    $isAdmin = $user && ($user->hasRole('Admin') || $user->hasPermission('admin.access'));

    $navItem = static function (string $file, string $icon, string $label) use ($current): string {
        $active = ($current === $file)
            ? 'bg-blue-700 text-white'
            : 'text-blue-100 hover:bg-blue-700 hover:text-white';
        return "<a href=\"{$file}\" class=\"flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors {$active}\">"
             . "<span class=\"text-base\">{$icon}</span><span>{$label}</span></a>";
    };

    $initials = $user ? e($user->getInitials()) : '?';
    $name     = $user ? e($user->getFullName()) : 'Guest';
    $email    = $user ? e($user->getEmail()) : '';

    echo <<<HTML
    <div class="flex min-h-screen">
      <!-- Sidebar -->
      <aside class="fixed top-0 left-0 h-full w-60 bg-gradient-to-b from-blue-900 to-blue-800 flex flex-col z-20 shadow-xl">
        <div class="p-5 border-b border-blue-700/50">
          <div class="text-white font-bold text-lg flex items-center gap-2">🔐 AuthManager</div>
          <div class="text-blue-300 text-xs mt-0.5">Full-Featured Demo</div>
        </div>
        <nav class="flex-1 p-3 space-y-1 overflow-y-auto">
          {$navItem('dashboard.php', '🏠', 'Dashboard')}
          {$navItem('security.php', '🛡️', 'Security &amp; 2FA')}
          {$navItem('jwt-demo.php', '🔑', 'JWT Demo')}
    HTML;

    if ($isAdmin) {
        echo '<div class="pt-3 pb-1 px-4 text-xs font-semibold text-blue-400 uppercase tracking-wider">Administration</div>';
        echo $navItem('admin.php', '⚙️', 'Admin Panel');
    }

    echo <<<HTML
        </nav>
        <div class="p-4 border-t border-blue-700/50">
          <div class="flex items-center gap-3 mb-3">
            <div class="w-9 h-9 rounded-full bg-blue-500 flex items-center justify-center text-white text-sm font-bold shrink-0">
              {$initials}
            </div>
            <div class="min-w-0">
              <div class="text-white text-sm font-medium truncate">{$name}</div>
              <div class="text-blue-300 text-xs truncate">{$email}</div>
            </div>
          </div>
          <a href="logout.php"
             class="flex items-center justify-center gap-2 px-3 py-2 bg-red-600/80 hover:bg-red-600 text-white text-sm rounded-xl transition-colors w-full">
            🚪 Sign Out
          </a>
        </div>
      </aside>
      <!-- Main content -->
      <div class="ml-60 flex-1 flex flex-col min-h-screen">
        <header class="bg-white border-b border-gray-200 px-8 py-4 flex items-center justify-between sticky top-0 z-10 shadow-sm">
          <h1 class="text-lg font-semibold text-gray-800">{$activeTitle}</h1>
          <div class="flex items-center gap-2 text-sm text-gray-500">
    HTML;

    if ($user) {
        foreach ($user->getRoles() as $role) {
            echo pill(e($role->getName()), 'indigo') . ' ';
        }
    }

    echo <<<HTML
          </div>
        </header>
        <main class="flex-1 p-8">
    HTML;
}

function sidebarEnd(): void
{
    echo "</main></div></div>\n";
}

function publicPage(string $title): void
{
    layoutStart($title, false);
}

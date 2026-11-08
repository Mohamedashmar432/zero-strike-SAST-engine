<?php
// ZS-PHP-012 look-alike: both cookie flags are set to true, in the options
// array form and in the legacy positional form, so nothing to report.
$token = bin2hex(random_bytes(16));
setcookie('remember', $token, [
    'expires' => time() + 86400,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);
setcookie('prefs', 'compact', time() + 3600, '/', '', true, true);

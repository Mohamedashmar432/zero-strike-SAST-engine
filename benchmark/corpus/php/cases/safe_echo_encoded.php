<?php
// ZS-PHP-004 look-alike: output encoding applied at the echo.
$q = $_GET['q'] ?? '';
echo '<p class="hint">Showing matches for ' . htmlspecialchars($q, ENT_QUOTES, 'UTF-8') . '</p>';
echo '<li>' . htmlentities($_GET['title']) . '</li>';
echo 'Page ' . intval($_GET['page']);

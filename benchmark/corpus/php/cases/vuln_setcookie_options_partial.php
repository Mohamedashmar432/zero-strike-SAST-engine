<?php
// ZS-PHP-012: the options array sets samesite and secure but not httponly.
$sessionId = $_GET['sid'];
setcookie('session', $sessionId, ['secure' => true, 'samesite' => 'Lax']);

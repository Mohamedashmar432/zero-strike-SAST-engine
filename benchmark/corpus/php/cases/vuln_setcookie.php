<?php
// ZS-PHP-012: insecure cookie — setcookie() called without verifying
// httponly/secure flags (engine can't inspect them, fires unconditionally)
$sessionId = $_GET['sid'];
setcookie("session", $sessionId);

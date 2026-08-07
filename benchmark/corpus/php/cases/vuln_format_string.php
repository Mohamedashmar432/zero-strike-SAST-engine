<?php
$username = $_GET['username'];
// ZS-PHP-017: the FORMAT STRING itself is attacker-controlled. The safe
// sprintf("User: %s", $username) idiom must not fire — see clean.php.
$greeting = sprintf("User: " . $username);
file_put_contents('greeting.log', $greeting);

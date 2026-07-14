<?php
$username = $_GET['username'];
// ZS-PHP-017: tainted format string — sprintf() called with a tainted argument
$greeting = sprintf("User: %s", $username);
file_put_contents('greeting.log', $greeting);

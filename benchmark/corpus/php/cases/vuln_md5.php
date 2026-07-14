<?php
// ZS-PHP-010: weak cryptographic hash — md5() used to hash a password
$password = $_POST['password'];
$hashed = md5($password);

<?php
// ZS-PHP-010: md5 over a request-supplied password.
$stored = md5($_POST['password']);

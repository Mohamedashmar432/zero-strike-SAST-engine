<?php
// ZS-PHP-015 look-alike: SERVER_PROTOCOL and REQUEST_METHOD are set by the web server, not the client.
header($_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found');
$m = $_SERVER['REQUEST_METHOD'];
header('Allow: ' . $m);

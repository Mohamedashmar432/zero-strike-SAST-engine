<?php
$check = $_GET['check'];
// ZS-PHP-021: assert() evaluates a tainted string as PHP code (PHP < 8.0)
assert($check);

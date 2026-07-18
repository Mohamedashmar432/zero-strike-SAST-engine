<?php
$target = $_POST['target'];
// ZS-PHP-020: command injection — passthru() with a tainted argument
passthru("nslookup " . $target);

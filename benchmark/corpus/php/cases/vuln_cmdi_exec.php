<?php
$host = $_GET['host'];
// ZS-PHP-019: command injection — exec() with a tainted argument
exec("ping -c 1 " . $host);

<?php
// ZS-PHP-015: open redirect — header() sends a tainted Location value
$next = $_GET['next'];
header("Location: " . $next);

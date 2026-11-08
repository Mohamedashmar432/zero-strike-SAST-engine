<?php
// ZS-PHP-006: one argument is escaped, the other is concatenated raw.
$out = shell_exec('convert ' . escapeshellarg($_GET['in']) . ' ' . $_GET['out']);

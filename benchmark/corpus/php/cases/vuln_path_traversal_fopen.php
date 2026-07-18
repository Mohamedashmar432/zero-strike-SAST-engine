<?php
$filename = $_GET['file'];
// ZS-PHP-023: path traversal — fopen() with a tainted path
$handle = fopen($filename, 'r');
fclose($handle);

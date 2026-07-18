<?php
$dest = $_POST['dest'];
// ZS-PHP-024: arbitrary file write — file_put_contents() with a tainted path
file_put_contents($dest, "log entry");

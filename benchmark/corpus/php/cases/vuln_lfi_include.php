<?php
// ZS-PHP-007: local file inclusion — $file traces back to $_GET
$file = $_GET['page'];
include($file);

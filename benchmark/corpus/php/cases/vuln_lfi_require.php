<?php
// ZS-PHP-008: local file inclusion — $file traces back to $_GET
$file = $_GET['page'];
require($file);

<?php
// ZS-PHP-006: command injection — shell_exec() with a tainted argument
$target = $_REQUEST['ip'];
shell_exec("ping -c 3 " . $target);

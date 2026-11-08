<?php
// ZS-PHP-033 look-alike: the path is a generated name, so a request value cannot choose the file.
$tmp = sys_get_temp_dir() . '/' . uniqid('up_', true) . $_POST['ext'];
rename($tmp, '/srv/spool/' . bin2hex(random_bytes(8)));
unlink($tmp);

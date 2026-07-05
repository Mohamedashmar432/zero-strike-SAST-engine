<?php
// ZS-PHP-001: command injection — cmd traces back to $_GET (untrusted input)
$cmd = $_GET['cmd'];
system($cmd);

<?php
// ZS-PHP-001/006/019/020 look-alike: the request value is wrapped in
// escapeshellarg() before it reaches the shell, so it is one inert word.
$host = escapeshellarg($_GET['host']);
$a = shell_exec('ping -c 1 ' . escapeshellarg($_GET['host']));
$b = system('nslookup ' . escapeshellarg($_GET['host']));
exec('whois ' . escapeshellarg($_GET['host']), $out);

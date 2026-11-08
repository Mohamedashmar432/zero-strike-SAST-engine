<?php
// ZS-PHP-013 look-alike: the value is a file name resolved by filesystem
// helpers (basename, realpath, storage_path), so it never names a remote host.
$name = basename($_GET['name']);
$root = realpath('/var/app/docs');
$path = realpath($root . '/' . $name);
$body = file_get_contents($path);

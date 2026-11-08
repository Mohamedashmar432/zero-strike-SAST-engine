<?php
// ZS-PHP-033 look-alike: basename() and realpath() keep the path inside a directory.
$file = basename($_GET['f']);
readfile('/var/app/docs/' . $file);
unlink('/var/app/uploads/' . basename($_POST['name']));
$path = realpath('/var/app/docs/' . $file);
$copy = file($path);

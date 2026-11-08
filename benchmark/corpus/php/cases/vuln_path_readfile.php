<?php
// ZS-PHP-033: request values reach file read and delete functions.
$file = $_GET['f'];
readfile('/var/app/docs/' . $file);
unlink('/var/app/uploads/' . $_POST['name']);

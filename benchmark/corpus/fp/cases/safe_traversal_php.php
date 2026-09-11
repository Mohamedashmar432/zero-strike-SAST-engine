<?php
// Negative fixture for the path-traversal rule family (ZS-PHP-007/008/023/
// 024). Every filesystem path below is a string literal. What is
// request-derived is the file *contents* — writing tainted bytes to a fixed
// path is not CWE-22/73.

$note = $_POST['note'];

// The headline case: constant destination, tainted contents. Before
// ZS-PHP-024 was pinned to argument 0 this reported an arbitrary file write
// because $note is tainted, even though the target never moves.
file_put_contents('/var/log/app/audit.log', $note, FILE_APPEND);

// Same shape through fopen(): the path is argument 0 and constant; 'a' is a
// mode, not a location.
$handle = fopen('/var/log/app/audit.log', 'a');
fwrite($handle, $note);
fclose($handle);

// Fixed includes cannot be steered at an uploaded or poisoned file.
include 'partials/header.php';
require 'lib/bootstrap.php';

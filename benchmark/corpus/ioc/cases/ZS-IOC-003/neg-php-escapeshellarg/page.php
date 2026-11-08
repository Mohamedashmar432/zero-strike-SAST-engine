<?php
$d = escapeshellarg($_GET['d']);
system('ls ' . $d);

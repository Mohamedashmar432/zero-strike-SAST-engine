<?php
// ZS-PHP-004: XSS sink — echo of a tainted value without escaping
$name = $_GET['name'];
echo $name;

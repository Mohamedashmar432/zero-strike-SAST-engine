<?php
$name = $_GET['name'];
// ZS-PHP-025: preg_replace() with the deprecated /e (eval) modifier
$result = preg_replace('/^(.*)$/e', 'ucwords("\1")', $name);

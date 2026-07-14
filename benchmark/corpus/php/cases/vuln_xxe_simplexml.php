<?php
// ZS-PHP-016: XXE — simplexml_load_string() parses tainted XML
$xml = $_POST['xml'];
$data = simplexml_load_string($xml);

<?php
// ZS-PHP-013: SSRF — file_get_contents() fetches a tainted URL
$url = $_GET['url'];
$body = file_get_contents($url);

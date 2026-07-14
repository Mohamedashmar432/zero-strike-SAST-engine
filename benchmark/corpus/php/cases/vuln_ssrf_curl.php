<?php
// ZS-PHP-014: SSRF — curl_setopt() sets CURLOPT_URL from a tainted value
$url = $_REQUEST['target'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);

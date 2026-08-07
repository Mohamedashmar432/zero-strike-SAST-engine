<?php
// ZS-PHP-029: weak HMAC algorithm.
$signature = hash_hmac('md5', $message, $key);

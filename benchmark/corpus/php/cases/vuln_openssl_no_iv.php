<?php
// ZS-PHP-028: openssl_encrypt() called without an IV argument.
$ciphertext = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA);

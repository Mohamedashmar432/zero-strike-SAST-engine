<?php
// ZS-PHP-027: ECB cipher mode leaks plaintext structure.
$ciphertext = openssl_encrypt($data, 'aes-128-ecb', $key, OPENSSL_RAW_DATA, $iv);
